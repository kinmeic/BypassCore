// BypassCore CLI: load routing config, then either test a routing decision
// (-test "tcp:host:port"), resolve a domain via the DNS subsystem
// (-resolve "example.com"), or run an observatory probe round (-observe).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	appdns "github.com/eugene/bypasscore/app/dns"
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
)

// Config is the top-level BypassCore config (outbounds + routing + dns).
type Config struct {
	Outbounds   []*appoutbound.Outbound `json:"outbounds"`
	Routing     conf.RouterConfig       `json:"routing"`
	DNS         *conf.DNSConfig         `json:"dns"`
	Observatory *observatory.Config     `json:"observatory"`
}

func main() {
	configPath := flag.String("config", "examples/config.example.json", "path to config file")
	testDest := flag.String("test", "", `test a routing decision, e.g. "tcp:www.google.com:443" or "udp:8.8.8.8:53"`)
	resolve := flag.String("resolve", "", `resolve a domain via the configured DNS subsystem, e.g. "example.com"`)
	observe := flag.Bool("observe", false, "run a single observatory probe round and print results")
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

	switch {
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
