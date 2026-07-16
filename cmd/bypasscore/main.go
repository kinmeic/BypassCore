// BypassCore CLI: load config, then either test a routing decision
// (-test "tcp:host:port"), resolve a domain (-resolve "domain"), run an
// observatory probe (-observe), or run as a daemon (-run).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/eugene/bypasscore/app/dialer"
	"github.com/eugene/bypasscore/app/dispatcher"
	appdns "github.com/eugene/bypasscore/app/dns"
	appinbound "github.com/eugene/bypasscore/app/inbound"
	appmetrics "github.com/eugene/bypasscore/app/metrics"
	"github.com/eugene/bypasscore/app/observatory"
	appoutbound "github.com/eugene/bypasscore/app/outbound"
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
	Metrics     *appmetrics.Config      `json:"metrics,omitempty"`
}

// version is overridden by release builds with -ldflags=-X main.version=... .
var version = "1.0.9"
var commit = "unknown"
var buildDate = "unknown"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "examples/config.example.json", "path to config file")
	testDest := flag.String("test", "", `test a routing decision, e.g. "tcp:www.google.com:443"`)
	resolve := flag.String("resolve", "", `resolve a domain via DNS, e.g. "example.com"`)
	observe := flag.Bool("observe", false, "run a single observatory probe round")
	runMode := flag.Bool("run", false, "run as a daemon (listen + dispatch)")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warning, error")
	showVersion := false
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&showVersion, "V", false, "print version and exit")
	flag.Parse()
	if err := errors.SetLogLevel(*logLevel); err != nil {
		return err
	}
	if showVersion {
		fmt.Printf("BypassCore %s (commit=%s, built=%s, go=%s)\n", version, commit, buildDate, runtime.Version())
		return nil
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return errors.New("load config: ").Base(err)
	}

	// Build the outbound manager from the descriptor table.
	registerDialerFactory()
	ohm := appoutbound.NewManager(&appoutbound.Config{Outbounds: cfg.Outbounds})
	if err := ohm.Validate(); err != nil {
		return errors.New("outbound config: ").Base(err)
	}
	defer ohm.Close()

	// Build the routing config.
	routerCfg, err := cfg.Routing.Build()
	if err != nil {
		return errors.New("build routing config: ").Base(err)
	}
	if err := validateRoutingTargets(routerCfg, ohm); err != nil {
		return errors.New("routing config: ").Base(err)
	}
	if err := validateRuntimeConfig(cfg); err != nil {
		return err
	}
	if *checkConfig {
		fmt.Println("configuration OK")
		return nil
	}

	// Build the DNS client. If a dns config is provided, use the full DNS
	// subsystem (multi-upstream, caching, DoH/DoT, etc.); otherwise fall back to
	// the system resolver.
	baseCtx := context.Background()
	var dnsClient featdns.Client
	var routedDNS *appdns.DNS
	if cfg.DNS != nil {
		dnsCfg, err := cfg.DNS.Build()
		if err != nil {
			return errors.New("build dns config: ").Base(err)
		}
		srv, err := appdns.New(baseCtx, dnsCfg)
		if err != nil {
			return errors.New("create dns server: ").Base(err)
		}
		if err := srv.Start(); err != nil {
			return errors.New("start dns server: ").Base(err)
		}
		defer srv.Close()
		dnsClient = srv
		routedDNS = srv
	} else {
		dnsClient = appdns.NewLocal()
	}

	// Optionally build the observatory.
	var observer *observatory.Observer
	if cfg.Observatory != nil && len(cfg.Observatory.SubjectSelector) > 0 {
		observer, err = observatory.New(baseCtx, cfg.Observatory, ohm)
		if err != nil {
			return errors.New("build observatory: ").Base(err)
		}
		_ = observer.Start()
		defer observer.Close()
	}

	// Construct the router via the DI shim: features are carried in the context.
	routerCtx := core.ContextWithFeatures(baseCtx, dnsClient, ohm, nil, observer)
	r := new(router.Router)
	if err := r.Init(routerCtx, routerCfg, dnsClient, ohm, nil); err != nil {
		return errors.New("init router: ").Base(err)
	}
	if routedDNS != nil {
		dnsDispatcher := dispatcher.New(r, ohm, nil)
		routedDNS.SetDialer(dnsDispatcher.DialOutbound)
	}

	// Choose the requested operating mode.
	switch {
	case *runMode:
		var metricsServer *appmetrics.Server
		if cfg.Metrics != nil {
			metricsServer, err = appmetrics.New(cfg.Metrics)
			if err != nil {
				return errors.New("metrics config: ").Base(err)
			}
			if err := metricsServer.Start(); err != nil {
				return errors.New("start metrics: ").Base(err)
			}
			defer metricsServer.Close()
		}
		reload := func() error { return reloadRoutingConfig(*configPath, cfg, r, ohm) }
		if err := runDaemonWithReload(r, ohm, dnsClient, cfg.Inbounds, baseCtx, reload); err != nil {
			return errors.New("run: ").Base(err)
		}
	case *resolve != "":
		if err := runResolve(dnsClient, *resolve); err != nil {
			return errors.New("resolve: ").Base(err)
		}
	case *observe:
		if err := runObserve(observer); err != nil {
			return errors.New("observe: ").Base(err)
		}
	case *testDest != "":
		if err := runTest(r, ohm, *testDest); err != nil {
			return errors.New("test: ").Base(err)
		}
	default:
		fmt.Println("BypassCore loaded. Use -test \"tcp:host:port\", -resolve \"domain\", or -observe.")
		fmt.Println("Outbounds:")
		for _, ob := range ohm.List() {
			fmt.Printf("  - %s (mode=%s)\n", ob.Tag, ob.Mode)
		}
	}
	return nil
}

func registerDialerFactory() {
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
			return socks.NewFromSettings(ob.Tag, ob.Upstream.Server, ob.Upstream.Settings)
		default:
			return blackhole.New(ob.Tag)
		}
	})
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
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg Config
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, errors.New("parse config.json").Base(err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("parse config.json: multiple JSON values")
		}
		return nil, errors.New("parse config.json").Base(err)
	}
	return &cfg, nil
}

func validateRoutingTargets(cfg *router.Config, ohm *appoutbound.Manager) error {
	if cfg == nil {
		return errors.New("nil routing config")
	}
	for _, rule := range cfg.Rule {
		if rule == nil {
			return errors.New("nil routing rule")
		}
		if tag := rule.GetTag(); tag != "" && ohm.GetOutbound(tag) == nil {
			return errors.New("routing rule references unknown outbound: ", tag)
		}
	}
	for _, balancer := range cfg.BalancingRule {
		if balancer == nil {
			return errors.New("nil balancing rule")
		}
		if tag := balancer.FallbackTag; tag != "" && ohm.GetOutbound(tag) == nil {
			return errors.New("balancer ", balancer.Tag, " references unknown fallback outbound: ", tag)
		}
		if len(ohm.Select(balancer.OutboundSelector)) == 0 {
			return errors.New("balancer ", balancer.Tag, " selectors match no outbounds")
		}
	}
	return nil
}

func validateRuntimeConfig(cfg *Config) error {
	seen := make(map[string]struct{}, len(cfg.Inbounds))
	for index, inbound := range cfg.Inbounds {
		if err := appinbound.ValidateConfig(inbound); err != nil {
			return errors.New("inbound[", index, "]: ").Base(err)
		}
		if _, exists := seen[inbound.Tag]; exists {
			return errors.New("duplicate inbound tag: ", inbound.Tag)
		}
		seen[inbound.Tag] = struct{}{}
		if _, err := dispatcher.NewSnifferWithOptions(inbound.Sniffing, inbound.SniffingTimeoutMs, inbound.SniffingMaxBytes); err != nil {
			return errors.New("invalid sniffing settings for inbound ", inbound.Tag).Base(err)
		}
	}
	if cfg.DNS != nil {
		if _, err := cfg.DNS.Build(); err != nil {
			return errors.New("build dns config: ").Base(err)
		}
	}
	if cfg.Metrics != nil {
		server, err := appmetrics.New(cfg.Metrics)
		if err != nil {
			return errors.New("metrics config: ").Base(err)
		}
		if err := server.Validate(); err != nil {
			return errors.New("metrics config: ").Base(err)
		}
	}
	return nil
}

func reloadRoutingConfig(path string, running *Config, r *router.Router, ohm *appoutbound.Manager) error {
	next, err := loadConfig(path)
	if err != nil {
		return errors.New("reload config: ").Base(err)
	}
	if err := validateRuntimeConfig(next); err != nil {
		return err
	}
	if !sameImmutableConfig(running, next) {
		return errors.New("reload rejected: outbounds, DNS, inbounds, observatory, and metrics require restart")
	}
	nextRouter, err := next.Routing.Build()
	if err != nil {
		return errors.New("build reloaded routing config: ").Base(err)
	}
	if err := validateRoutingTargets(nextRouter, ohm); err != nil {
		return errors.New("reloaded routing config: ").Base(err)
	}
	if err := r.ReloadRules(nextRouter, false); err != nil {
		return errors.New("apply reloaded routing config: ").Base(err)
	}
	running.Routing = next.Routing
	return nil
}

func sameImmutableConfig(left, right *Config) bool {
	leftValue := struct {
		Outbounds   []*appoutbound.Outbound
		DNS         *conf.DNSConfig
		Inbounds    []*appinbound.Config
		Observatory *observatory.Config
		Metrics     *appmetrics.Config
	}{left.Outbounds, left.DNS, left.Inbounds, left.Observatory, left.Metrics}
	rightValue := struct {
		Outbounds   []*appoutbound.Outbound
		DNS         *conf.DNSConfig
		Inbounds    []*appinbound.Config
		Observatory *observatory.Config
		Metrics     *appmetrics.Config
	}{right.Outbounds, right.DNS, right.Inbounds, right.Observatory, right.Metrics}
	leftJSON, leftErr := json.Marshal(leftValue)
	rightJSON, rightErr := json.Marshal(rightValue)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
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

func runObserve(observer *observatory.Observer) error {
	if observer == nil {
		fmt.Println("No observatory configured (set config \"observatory.subjectSelector\").")
		return nil
	}
	// Give the background loop time to complete one probe round.
	time.Sleep(6 * time.Second)
	result, err := observer.GetObservation(context.Background())
	if err != nil {
		return err
	}
	obs, ok := result.(*observatory.ObservationResult)
	if !ok {
		return errors.New("unexpected observation type")
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
	return nil
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

// runDaemon starts all transparent-proxy and DNS inbound listeners and blocks
// until a signal is received.
func runDaemon(r *router.Router, ohm *appoutbound.Manager, dnsClient featdns.Client, inbounds []*appinbound.Config, baseCtx context.Context) error {
	return runDaemonWithReload(r, ohm, dnsClient, inbounds, baseCtx, nil)
}

func runDaemonWithReload(r *router.Router, ohm *appoutbound.Manager, dnsClient featdns.Client, inbounds []*appinbound.Config, baseCtx context.Context, reload func() error) error {
	// Start all inbound listeners.
	type listener interface {
		Start() error
		Close() error
	}
	var listeners []listener
	closeListeners := func() {
		for i := len(listeners) - 1; i >= 0; i-- {
			_ = listeners[i].Close()
		}
	}
	for _, ibCfg := range inbounds {
		if ibCfg == nil {
			closeListeners()
			return errors.New("nil inbound configuration")
		}
		var ln listener
		inboundType := strings.ToLower(strings.TrimSpace(ibCfg.Type))
		if inboundType == "dns" || inboundType == "dot" || inboundType == "doh" {
			ln = appinbound.NewDNS(ibCfg, dnsClient)
		} else {
			// Sniffing is an inbound property. Give each transparent listener its
			// own dispatcher so one inbound cannot affect another.
			sniffer, err := dispatcher.NewSnifferWithOptions(ibCfg.Sniffing, ibCfg.SniffingTimeoutMs, ibCfg.SniffingMaxBytes)
			if err != nil {
				closeListeners()
				return errors.New("invalid sniffing settings for inbound ", ibCfg.Tag).Base(err)
			}
			d := dispatcher.New(r, ohm, sniffer)
			ln = appinbound.New(ibCfg, d)
		}
		if err := ln.Start(); err != nil {
			closeListeners()
			return errors.New("failed to start inbound ", ibCfg.Tag).Base(err)
		}
		listeners = append(listeners, ln)
	}

	if len(listeners) == 0 {
		return errors.New("no inbounds configured; nothing to listen on")
	}

	fmt.Printf("BypassCore running with %d inbound(s). Ctrl+C to stop.\n", len(listeners))

	// SIGHUP atomically replaces routing rules after full validation. Listener,
	// DNS and outbound mutations are rejected because they require rebinding or
	// draining live resources and therefore need an explicit restart.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	for {
		select {
		case received := <-sigCh:
			if received == syscall.SIGHUP {
				if reload == nil {
					continue
				}
				if err := reload(); err != nil {
					errors.LogErrorInner(context.Background(), err, "configuration reload failed; keeping previous routing rules")
				} else {
					errors.LogInfo(context.Background(), "routing rules reloaded")
				}
				continue
			}
		case <-baseCtx.Done():
		}
		break
	}

	fmt.Println("\nShutting down...")
	closeListeners()
	return nil
}
