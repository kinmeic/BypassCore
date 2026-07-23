// BypassCore CLI: load config, then either test a routing decision
// (-test "tcp:host:port"), resolve a domain (-resolve "domain"), measure a TCP
// handshake (-tcp-probe "host:port"), run an observatory probe (-observe), or
// run as a daemon (-run).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/eugene/bypasscore/app/control"
	"github.com/eugene/bypasscore/app/dialer"
	"github.com/eugene/bypasscore/app/dispatcher"
	appdns "github.com/eugene/bypasscore/app/dns"
	"github.com/eugene/bypasscore/app/dnsevent"
	"github.com/eugene/bypasscore/app/dnsnftset"
	appinbound "github.com/eugene/bypasscore/app/inbound"
	appmetrics "github.com/eugene/bypasscore/app/metrics"
	"github.com/eugene/bypasscore/app/observatory"
	appoutbound "github.com/eugene/bypasscore/app/outbound"
	"github.com/eugene/bypasscore/app/router"
	"github.com/eugene/bypasscore/app/tcpprobe"
	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	bcsession "github.com/eugene/bypasscore/common/session"
	"github.com/eugene/bypasscore/common/wgkey"
	"github.com/eugene/bypasscore/core"
	featdns "github.com/eugene/bypasscore/features/dns"
	featrouting "github.com/eugene/bypasscore/features/routing"
	routingsession "github.com/eugene/bypasscore/features/routing/session"
	"github.com/eugene/bypasscore/infra/conf"
	"github.com/eugene/bypasscore/proxy/blackhole"
	"github.com/eugene/bypasscore/proxy/freedom"
	"github.com/eugene/bypasscore/proxy/socks"
	wgoutbound "github.com/eugene/bypasscore/proxy/wireguard"
)

// Config is the top-level BypassCore config (outbounds + routing + dns + inbounds).
type Config struct {
	Outbounds        []*appoutbound.Outbound `json:"outbounds"`
	Routing          conf.RouterConfig       `json:"routing"`
	DNS              *conf.DNSConfig         `json:"dns"`
	Inbounds         []*appinbound.Config    `json:"inbounds"`
	Observatory      *observatory.Config     `json:"observatory"`
	Metrics          *appmetrics.Config      `json:"metrics,omitempty"`
	Control          *control.Config         `json:"control,omitempty"`
	DNSResultEvents  *dnsevent.Config        `json:"dnsResultEvents,omitempty"`
	DNSResultNFTSets *dnsnftset.Config       `json:"dnsResultNFTSets,omitempty"`
}

// version is overridden by release builds with -ldflags=-X main.version=... .
var version = "1.4.0"
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
	tcpProbe := flag.String("tcp-probe", "", `measure one TCP handshake, e.g. "example.com:443"`)
	tcpProbeTimeout := flag.Duration("tcp-probe-timeout", tcpprobe.DefaultTimeout, "TCP probe timeout")
	runMode := flag.Bool("run", false, "run as a daemon (listen + dispatch)")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warning, error")
	showVersion := false
	showCapabilities := flag.Bool("capabilities", false, "print supported capabilities and exit")
	jsonOutput := flag.Bool("json", false, "use JSON output where supported")
	wireGuardKeypair := flag.Bool("wireguard-generate-keypair", false, "generate a WireGuard private/public key pair and exit")
	wireGuardPSK := flag.Bool("wireguard-generate-psk", false, "generate a WireGuard preshared key and exit")
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
	if *showCapabilities {
		value := capabilities()
		if *jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(value)
		}
		fmt.Printf("BypassCore %s, config schema %d\n", value.Version, value.ConfigSchema)
		for _, feature := range value.Features {
			fmt.Println(feature)
		}
		return nil
	}
	if *tcpProbe != "" {
		return runTCPProbe(*tcpProbe, *tcpProbeTimeout, *jsonOutput)
	}
	if *wireGuardKeypair && *wireGuardPSK {
		return errors.New("choose only one WireGuard key generation operation")
	}
	if *wireGuardKeypair {
		private, err := wgkey.GeneratePrivate()
		if err != nil {
			return err
		}
		public, err := wgkey.Public(private)
		if err != nil {
			return err
		}
		return writeKeyResult(*jsonOutput, map[string]string{
			"secretKey": wgkey.Encode(private),
			"publicKey": wgkey.Encode(public),
		})
	}
	if *wireGuardPSK {
		key, err := wgkey.GeneratePreShared()
		if err != nil {
			return err
		}
		return writeKeyResult(*jsonOutput, map[string]string{"preSharedKey": wgkey.Encode(key)})
	}

	cfg, configHash, err := loadConfigAndHash(*configPath)
	if err != nil {
		return errors.New("load config: ").Base(err)
	}

	// Build the outbound manager from the descriptor table.
	registerDialerFactory()
	if *runMode {
		return runRuntimeDaemon(context.Background(), *configPath, cfg, configHash)
	}
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
	var builtDNSConfig *appdns.Config
	if cfg.DNS != nil {
		builtDNSConfig, err = cfg.DNS.Build()
		if err != nil {
			return errors.New("build dns config: ").Base(err)
		}
	}
	if err := validateRuntimeConfigWithBuiltDNS(cfg, ohm, builtDNSConfig); err != nil {
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
	if builtDNSConfig != nil {
		srv, err := appdns.New(baseCtx, builtDNSConfig)
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
		routedDNS.SetTaggedDialer(func(ctx context.Context, destination bcnet.Destination, outboundTag string) (net.Conn, error) {
			if outboundTag == "" {
				return dnsDispatcher.DialOutbound(ctx, destination)
			}
			selected := ohm.GetDialer(outboundTag)
			if selected == nil {
				return nil, errors.New("DNS outbound not found: ", outboundTag)
			}
			return selected.Dial(ctx, destination)
		})
	}

	// Choose the requested operating mode.
	switch {
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
		case appoutbound.ModeWireGuard:
			return wgoutbound.New(ob.Tag, ob.WireGuard)
		default:
			return blackhole.New(ob.Tag)
		}
	})
}

func writeKeyResult(jsonOutput bool, result map[string]string) error {
	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if value := result["secretKey"]; value != "" {
		fmt.Println("secretKey=" + value)
		fmt.Println("publicKey=" + result["publicKey"])
		return nil
	}
	fmt.Println("preSharedKey=" + result["preSharedKey"])
	return nil
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

func runTCPProbe(target string, timeout time.Duration, jsonOutput bool) error {
	host, rawPort, err := net.SplitHostPort(target)
	if err != nil {
		return errors.New("TCP probe target must use host:port notation").Base(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return errors.New("TCP probe port is invalid").Base(err)
	}
	result, err := tcpprobe.Connect(context.Background(), host, port, timeout)
	if err != nil {
		return err
	}
	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	fmt.Printf("connected to %s in %.3f ms\n", result.RemoteAddress, result.LatencyMs)
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
	if tag := cfg.GetFinalOutboundTag(); tag != "" && ohm.GetOutbound(tag) == nil {
		return errors.New("routing finalOutboundTag references unknown outbound: ", tag)
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

func validateRuntimeConfigWithOutbounds(cfg *Config, ohm *appoutbound.Manager) error {
	var dnsConfig *appdns.Config
	if cfg.DNS != nil {
		var err error
		dnsConfig, err = cfg.DNS.Build()
		if err != nil {
			return errors.New("build dns config: ").Base(err)
		}
	}
	return validateRuntimeConfigWithBuiltDNS(cfg, ohm, dnsConfig)
}

func validateRuntimeConfigWithBuiltDNS(cfg *Config, ohm *appoutbound.Manager, dnsConfig *appdns.Config) error {
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
	if dnsConfig != nil {
		if ohm != nil {
			for _, server := range dnsConfig.NameServer {
				if tag := server.GetOutboundTag(); tag != "" && ohm.GetOutbound(tag) == nil {
					return errors.New("DNS server ", server.GetTag(), " references unknown outbound: ", tag)
				}
				if tag := server.GetOutboundTag(); tag != "" && dnsServerIsLocal(server.Address.AsDestination()) {
					return errors.New("DNS server ", server.GetTag(), " cannot combine outboundTag with localhost or a +local transport")
				}
			}
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
	if cfg.Control != nil && cfg.Control.Enabled {
		if err := control.Validate(cfg.Control); err != nil {
			return errors.New("control config: ").Base(err)
		}
	}
	if cfg.DNSResultEvents != nil {
		if cfg.DNS == nil {
			return errors.New("dnsResultEvents requires a DNS configuration")
		}
		if err := dnsevent.Validate(cfg.DNSResultEvents); err != nil {
			return errors.New("dnsResultEvents config: ").Base(err)
		}
	}
	if cfg.DNSResultNFTSets != nil {
		if cfg.DNS == nil || dnsConfig == nil {
			return errors.New("dnsResultNFTSets requires a DNS configuration")
		}
		if err := dnsnftset.Validate(cfg.DNSResultNFTSets); err != nil {
			return errors.New("dnsResultNFTSets config: ").Base(err)
		}
		availableTags := make(map[string]struct{}, len(dnsConfig.NameServer))
		for _, server := range dnsConfig.NameServer {
			tag := strings.TrimSpace(server.GetTag())
			if tag == "" {
				tag = "_default"
			}
			availableTags[tag] = struct{}{}
		}
		for policyIndex, policy := range cfg.DNSResultNFTSets.Policies {
			for _, rawTag := range policy.ServerTags {
				tag := strings.TrimSpace(rawTag)
				if _, exists := availableTags[tag]; !exists {
					return errors.New("dnsResultNFTSets policy ", policyIndex, " references unknown DNS server tag: ", tag)
				}
			}
		}
	}
	return nil
}

func dnsServerIsLocal(destination bcnet.Destination) bool {
	if !destination.Address.Family().IsDomain() {
		return false
	}
	raw := strings.ToLower(destination.Address.Domain())
	if raw == "localhost" {
		return true
	}
	separator := strings.Index(raw, "://")
	return separator > 0 && strings.HasSuffix(raw[:separator], "+local")
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
	if route.IsFallback() {
		fmt.Printf("Matched rule: - (final/default)\n")
	} else {
		fmt.Printf("Matched rule: %s\n", orDash(ruleTag))
	}
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

func runDaemonWithReload(r featrouting.Router, ohm dispatcher.DialerManager, dnsClient featdns.Client, inbounds []*appinbound.Config, baseCtx context.Context, reload func() error) error {
	// Start all inbound listeners.
	type listener interface {
		Start() error
		Close() error
	}
	var listeners []listener
	type inboundFailure struct {
		tag string
		err error
	}
	failureCh := make(chan inboundFailure, len(inbounds))
	monitorCtx, stopMonitors := context.WithCancel(context.Background())
	defer stopMonitors()
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
		if live, ok := r.(*runtimeService); ok {
			if reloadable, ok := ln.(reloadableInbound); ok {
				live.registerInbound(reloadable)
				go func(tag string, failures <-chan error) {
					select {
					case err := <-failures:
						if err != nil {
							failureCh <- inboundFailure{tag: tag, err: err}
						}
					case <-monitorCtx.Done():
					}
				}(ibCfg.Tag, reloadable.Failures())
			}
		}
		listeners = append(listeners, ln)
	}

	if len(listeners) == 0 {
		return errors.New("no inbounds configured; nothing to listen on")
	}
	if live, ok := r.(*runtimeService); ok {
		live.listeners.Store(true)
		defer live.listeners.Store(false)
	}

	fmt.Printf("BypassCore running with %d inbound(s). Ctrl+C to stop.\n", len(listeners))

	// SIGHUP transactionally replaces the runtime snapshot after full validation.
	// Existing flows drain on the old snapshot; listener binding changes are
	// rejected with restart_required while mutable inbound policies are updated.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	for {
		select {
		case failure := <-failureCh:
			closeListeners()
			return errors.New("inbound ", failure.tag, " failed; daemon must restart: ").Base(failure.err)
		case received := <-sigCh:
			if received == syscall.SIGHUP {
				if reload == nil {
					continue
				}
				if err := reload(); err != nil {
					errors.LogErrorInner(context.Background(), err, "configuration reload failed; keeping the previous runtime snapshot")
				} else {
					errors.LogInfo(context.Background(), "runtime configuration reloaded")
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
