// BypassCore CLI: load config, then either test a routing decision
// (-test "tcp:host:port"), resolve a domain (-resolve "domain"), run an
// observatory probe (-observe), or run as a daemon (-run).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eugene/bypasscore/app/dispatcher"
	appdns "github.com/eugene/bypasscore/app/dns"
	"github.com/eugene/bypasscore/app/dialer"
	appinbound "github.com/eugene/bypasscore/app/inbound"
	appoutbound "github.com/eugene/bypasscore/app/outbound"
	"github.com/eugene/bypasscore/app/observatory"
	"github.com/eugene/bypasscore/app/router"
	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	bcsession "github.com/eugene/bypasscore/common/session"
	"github.com/eugene/bypasscore/core"
	featdns "github.com/eugene/bypasscore/features/dns"
	routingsession "github.com/eugene/bypasscore/features/routing/session"
	"github.com/eugene/bypasscore/infra/conf"
	"github.com/eugene/bypasscore/proxy/blackhole"
	"github.com/eugene/bypasscore/proxy/freedom"
	"github.com/eugene/bypasscore/proxy/socks"
)

// Config is the top-level BypassCore config (outbounds + routing + dns + inbounds).
type Config struct {
	Outbounds   []*appoutbound.Outbound `json:"outbounds"`
	Routing     conf.RouterConfig       `json:"routing"`
	DNS         *conf.DNSConfig         `json:"dns"`
	Inbounds    []*appinbound.Config    `json:"inbounds"`
	Observatory *observatory.Config     `json:"observatory"`
}

func main() {
	configPath := flag.String("config", "examples/config.example.json", "path to config file")
	testDest := flag.String("test", "", `test a routing decision, e.g. "tcp:www.google.com:443"`)
	resolve := flag.String("resolve", "", `resolve a domain via DNS, e.g. "example.com"`)
	observe := flag.Bool("observe", false, "run a single observatory probe round")
	runMode := flag.Bool("run", false, "run as a daemon (listen + dispatch)")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fail("load config: ", err)
	}

	// Build the outbound manager from the descriptor table.
	ohm := appoutbound.NewManager(&appoutbound.Config{Outbounds: cfg.Outbounds})
	if err := ohm.Validate(); err != nil {
		fail("outbound config: ", err)
	}

	// Build the routing config.
	routerCfg, err := cfg.Routing.Build()
	if err != nil {
		fail("build routing config: ", err)
	}

	// Build the DNS client. If a dns config is provided, use the full DNS
	// subsystem (multi-upstream, caching, DoH/DoT, etc.); otherwise fall back to
	// the system resolver.
	baseCtx := context.Background()
	var dnsClient featdns.Client
	if cfg.DNS != nil {
		dnsCfg, err := cfg.DNS.Build()
		if err != nil {
			fail("build dns config: ", err)
		}
		srv, err := appdns.New(baseCtx, dnsCfg)
		if err != nil {
			fail("create dns server: ", err)
		}
		if err := srv.Start(); err != nil {
			fail("start dns server: ", err)
		}
		defer srv.Close()
		dnsClient = srv
	} else {
		dnsClient = appdns.NewLocal()
	}

	// Optionally build the observatory.
	var observer *observatory.Observer
	if cfg.Observatory != nil && len(cfg.Observatory.SubjectSelector) > 0 {
		observer, err = observatory.New(baseCtx, cfg.Observatory, ohm)
		if err != nil {
			fail("build observatory: ", err)
		}
		_ = observer.Start()
		defer observer.Close()
	}

	// Construct the router via the DI shim: features are carried in the context.
	routerCtx := core.ContextWithFeatures(baseCtx, dnsClient, ohm, nil, observer)
	r := new(router.Router)
	if err := r.Init(routerCtx, routerCfg, dnsClient, ohm, nil); err != nil {
		fail("init router: ", err)
	}

	// Register the dialer factory so outbound.Manager can produce freedom/blackhole
	// dialers from the descriptor table.
	appoutbound.SetDialerFactory(func(ob *appoutbound.Outbound) dialer.Dialer {
		bindIP := ""
		bindIface := ""
		if ob.Bind != nil {
			bindIP = ob.Bind.LocalIP
			bindIface = ob.Bind.Interface
		}
		switch ob.Mode {
		case appoutbound.ModeBlackhole:
			return blackhole.New(ob.Tag)
		case appoutbound.ModeFreedom:
			return freedom.New(ob.Tag, bindIP, bindIface)
		case appoutbound.ModeProxy:
			// Proxy mode: dial to upstream SOCKS5 server (e.g. naiveproxy local socks).
			if ob.Upstream == nil || ob.Upstream.Server == "" {
				return blackhole.New(ob.Tag)
			}
			return socks.NewFromSettings(ob.Tag, ob.Upstream.Server, ob.Upstream.Settings)
		default:
			return freedom.New(ob.Tag, bindIP, bindIface)
		}
	})

	switch {
	case *runMode:
		if err := runDaemon(r, ohm, cfg.Inbounds, baseCtx); err != nil {
			fail("run: ", err)
		}
	case *resolve != "":
		if err := runResolve(dnsClient, *resolve); err != nil {
			fail("resolve: ", err)
		}
	case *observe:
		runObserve(observer)
	case *testDest != "":
		if err := runTest(r, ohm, *testDest); err != nil {
			fail("test: ", err)
		}
	default:
		fmt.Println("BypassCore loaded. Use -test \"tcp:host:port\", -resolve \"domain\", or -observe.")
		fmt.Println("Outbounds:")
		for _, ob := range ohm.List() {
			fmt.Printf("  - %s (mode=%s)\n", ob.Tag, ob.Mode)
		}
	}
}

func runResolve(dnsClient featdns.Client, domain string) error {
	ips, ttl, err := dnsClient.LookupIP(domain, featdns.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil {
		return errors.New("lookup failed for ", domain).Base(err)
	}
	fmt.Printf("Domain: %s\n", domain)
	fmt.Printf("Result: %d IP(s), TTL=%ds\n", len(ips), ttl)
	for _, ip := range ips {
		fmt.Printf("  %s\n", ip)
	}
	return nil
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, errors.New("parse config.json").Base(err)
	}
	return &cfg, nil
}

func runTest(r *router.Router, ohm *appoutbound.Manager, dest string) error {
	target, err := bcnet.ParseDestination(dest)
	if err != nil {
		return errors.New("parse destination").Base(err)
	}

	// Build a routing context carrying the target destination.
	rctx := &routingsession.Context{
		Outbound: &bcsession.Outbound{Target: target},
	}

	route, err := r.PickRoute(rctx)
	if err != nil {
		fmt.Printf("Target:  %s\n", target.String())
		fmt.Printf("Result:  no matching rule (default/fallback)\n")
		fmt.Printf("Reason:  %v\n", err)
		return nil
	}

	tag := route.GetOutboundTag()
	ruleTag := route.GetRuleTag()

	fmt.Printf("Target:       %s\n", target.String())
	if target.Address.Family().IsDomain() {
		fmt.Printf("  domain:     %s\n", target.Address.Domain())
	} else {
		fmt.Printf("  ip:         %s\n", target.Address.IP())
	}
	fmt.Printf("  port:       %d (%s)\n", target.Port, target.Network)
	fmt.Printf("Matched rule: %s\n", orDash(ruleTag))
	fmt.Printf("Outbound tag: %s\n", tag)
	if ob := ohm.GetOutbound(tag); ob != nil {
		describeOutbound(ob)
	}
	return nil
}

func describeOutbound(ob *appoutbound.Outbound) {
	fmt.Printf("Outbound:     %s (mode=%s)\n", ob.Tag, ob.Mode)
	if ob.Bind != nil {
		if ob.Bind.Interface != "" {
			fmt.Printf("  bind iface: %s\n", ob.Bind.Interface)
		}
		if ob.Bind.LocalIP != "" {
			fmt.Printf("  bind ip:    %s\n", ob.Bind.LocalIP)
		}
	}
	if ob.Upstream != nil {
		fmt.Printf("  upstream:   %s @ %s\n", ob.Upstream.Protocol, ob.Upstream.Server)
	}
}

func runObserve(observer *observatory.Observer) {
	if observer == nil {
		fmt.Println("No observatory configured (set config \"observatory.subjectSelector\").")
		return
	}
	// Give the background loop time to complete one probe round.
	time.Sleep(6 * time.Second)
	result, err := observer.GetObservation(context.Background())
	if err != nil {
		fail("get observation: ", err)
	}
	obs, ok := result.(*observatory.ObservationResult)
	if !ok {
		fail("unexpected observation type")
	}
	fmt.Printf("%-20s %-8s %-10s %s\n", "OUTBOUND", "ALIVE", "DELAY(ms)", "REASON")
	fmt.Println(repeat("-", 60))
	for _, s := range obs.Status {
		alive := "no"
		delay := "-"
		if s.Alive {
			alive = "yes"
			delay = fmt.Sprintf("%d", s.Delay)
		}
		fmt.Printf("%-20s %-8s %-10s %s\n", s.OutboundTag, alive, delay, s.LastErrorReason)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func fail(msg ...interface{}) {
	fmt.Fprintln(os.Stderr, "error:", fmt.Sprint(msg...))
	os.Exit(1)
}

// runDaemon starts all inbound listeners and blocks until a signal is received.
// This is the "bypasscore run -c config.json" mode: the process stays alive
// as a transparent proxy, accepting tproxy/redirect connections and routing
// them via the router to outbound handlers.
func runDaemon(r *router.Router, ohm *appoutbound.Manager, inbounds []*appinbound.Config, baseCtx context.Context) error {
	// Build the sniffer (enabled if any inbound has sniffing=true).
	sniffEnabled := false
	for _, ib := range inbounds {
		if ib.Sniffing {
			sniffEnabled = true
			break
		}
	}
	sniffer := dispatcher.NewSniffer(sniffEnabled)

	// Build the dispatcher (data-plane hub).
	d := dispatcher.New(r, ohm, sniffer)

	// Start all inbound listeners.
	var listeners []*appinbound.Listener
	for _, ibCfg := range inbounds {
		ln := appinbound.New(ibCfg, d)
		if err := ln.Start(); err != nil {
			// Close already-started listeners before failing.
			for _, l := range listeners {
				_ = l.Close()
			}
			return errors.New("failed to start inbound ", ibCfg.Tag).Base(err)
		}
		listeners = append(listeners, ln)
	}

	if len(listeners) == 0 {
		return errors.New("no inbounds configured; nothing to listen on")
	}

	fmt.Printf("BypassCore running with %d inbound(s). Ctrl+C to stop.\n", len(listeners))

	// Block until SIGINT or SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")
	for _, ln := range listeners {
		_ = ln.Close()
	}
	return nil
}
