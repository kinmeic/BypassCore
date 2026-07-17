package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	stderrors "errors"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eugene/bypasscore/app/control"
	"github.com/eugene/bypasscore/app/dialer"
	appdns "github.com/eugene/bypasscore/app/dns"
	"github.com/eugene/bypasscore/app/dnsevent"
	"github.com/eugene/bypasscore/app/dnsnftset"
	appinbound "github.com/eugene/bypasscore/app/inbound"
	appmetrics "github.com/eugene/bypasscore/app/metrics"
	"github.com/eugene/bypasscore/app/observatory"
	appoutbound "github.com/eugene/bypasscore/app/outbound"
	"github.com/eugene/bypasscore/app/router"
	"github.com/eugene/bypasscore/common"
	"github.com/eugene/bypasscore/common/errors"
	commonmetrics "github.com/eugene/bypasscore/common/metrics"
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/common/serial"
	bcsession "github.com/eugene/bypasscore/common/session"
	"github.com/eugene/bypasscore/core"
	featdns "github.com/eugene/bypasscore/features/dns"
	"github.com/eugene/bypasscore/features/routing"
	routingsession "github.com/eugene/bypasscore/features/routing/session"
)

const runtimeDrainTimeout = 30 * time.Second
const maxRetiredSnapshots = 8
const maxConfigBytes = 16 << 20

func capabilities() control.Capabilities {
	return control.Capabilities{
		Version:      version,
		ConfigSchema: 4,
		Features: []string{
			"control-unix-http-json", "dns-inbound", "raw-dns", "metrics",
			"routing-reload", "full-reload", "runtime-snapshot-reload", "inbound-parameter-reload", "dns-outbound-tag",
			"routing-final-outbound", "socks5-udp", "transparent-tcp-redirect",
			"transparent-tcp-udp-tproxy", "dns-result-unixgram", "dns-result-resync", "dns-result-nftset", "dns-result-nftset-probe", "observatory", "ready-status", "inbound-health", "reload-if-match", "ipv6",
		},
	}
}

func runRuntimeDaemon(ctx context.Context, configPath string, cfg *Config, hash string) error {
	service, err := newRuntimeService(ctx, configPath, cfg, hash)
	if err != nil {
		return err
	}
	defer service.Close()

	var metricsServer *appmetrics.Server
	if cfg.Metrics != nil {
		metricsServer, err = appmetrics.New(cfg.Metrics)
		if err != nil {
			return errors.New("metrics config: ").Base(err)
		}
		if err := metricsServer.Start(); err != nil {
			return errors.New("start metrics: ").Base(err)
		}
		service.metrics = metricsServer
		metricsServer.SetReadiness(func() bool {
			snapshot, err := service.acquire()
			if err != nil {
				return false
			}
			defer snapshot.release()
			_, ready := service.inboundHealth(len(snapshot.config.Inbounds))
			if snapshot.dnsNFTSets != nil {
				ready = ready && snapshot.dnsNFTSets.Status().Ready
			}
			return ready
		})
		defer metricsServer.Close()
	}
	var controlServer *control.Server
	if cfg.Control != nil && cfg.Control.Enabled {
		controlServer, err = control.New(cfg.Control, service, capabilities())
		if err != nil {
			return errors.New("control config: ").Base(err)
		}
		if err := controlServer.Start(); err != nil {
			return errors.New("start control: ").Base(err)
		}
		defer controlServer.Close()
	}
	reload := func() error { _, err := service.Reload(context.Background(), nil); return err }
	return runDaemonWithReload(service, service, service, cfg.Inbounds, ctx, reload)
}

type runtimeSnapshot struct {
	config     *Config
	hash       string
	revision   uint64
	router     *router.Router
	outbound   *appoutbound.Manager
	dns        featdns.Client
	routedDNS  *appdns.DNS
	observer   *observatory.Observer
	dnsEvents  *dnsevent.Sink
	dnsNFTSets *dnsnftset.Writer

	refs       atomic.Int64
	retired    atomic.Bool
	forced     atomic.Bool
	closed     atomic.Bool
	closeOnce  sync.Once
	connMu     sync.Mutex
	conns      map[*leasedConn]struct{}
	timerMu    sync.Mutex
	drainTimer *time.Timer
}

type runtimeService struct {
	configPath       string
	mu               sync.RWMutex
	current          *runtimeSnapshot
	reloadBusy       atomic.Bool
	closed           bool
	startedAt        time.Time
	listeners        atomic.Bool
	lastReloadMu     sync.RWMutex
	lastReload       reloadStatus
	inboundMu        sync.RWMutex
	inbounds         []reloadableInbound
	metrics          *appmetrics.Server
	outboundStatusMu sync.RWMutex
	outboundStatus   map[string]outboundRuntimeStatus
	ctx              context.Context
	cancel           context.CancelFunc
	retiredMu        sync.Mutex
	retired          []*runtimeSnapshot
	dnsEventSequence atomic.Uint64
	dnsResultMu      sync.Mutex
	dnsResults       map[string]dnsevent.Event
}

type reloadableInbound interface {
	Reload(*appinbound.Config) error
	PrepareReload(*appinbound.Config) (func() error, error)
	Status() appinbound.HealthStatus
	Failures() <-chan error
}

type reloadStatus struct {
	Success bool      `json:"success"`
	At      time.Time `json:"at,omitempty"`
	Error   string    `json:"error,omitempty"`
}

type outboundRuntimeStatus struct {
	Tag         string    `json:"tag"`
	LastSuccess time.Time `json:"lastSuccess,omitempty"`
	LastFailure time.Time `json:"lastFailure,omitempty"`
	LastError   string    `json:"lastError,omitempty"`
}

func newRuntimeService(ctx context.Context, configPath string, cfg *Config, hash string) (*runtimeService, error) {
	lifecycleCtx, cancel := context.WithCancel(ctx)
	s := &runtimeService{configPath: configPath, startedAt: time.Now(), outboundStatus: make(map[string]outboundRuntimeStatus), dnsResults: make(map[string]dnsevent.Event), ctx: lifecycleCtx, cancel: cancel}
	snapshot, err := s.buildSnapshot(lifecycleCtx, cfg, 1, hash, true)
	if err != nil {
		cancel()
		return nil, err
	}
	if err := snapshot.activate(); err != nil {
		snapshot.retire()
		cancel()
		return nil, err
	}
	s.current = snapshot
	commonmetrics.Set("bypasscore_config_revision", 1)
	return s, nil
}

func (s *runtimeService) buildSnapshot(ctx context.Context, cfg *Config, revision uint64, hash string, runtimeResources bool) (*runtimeSnapshot, error) {
	manager := appoutbound.NewManager(&appoutbound.Config{Outbounds: cfg.Outbounds})
	fail := func(err error) (*runtimeSnapshot, error) {
		_ = manager.Close()
		return nil, err
	}
	if err := manager.Validate(); err != nil {
		return fail(errors.New("outbound config: ").Base(err))
	}
	routerCfg, err := cfg.Routing.Build()
	if err != nil {
		return fail(errors.New("build routing config: ").Base(err))
	}
	if err := validateRoutingTargets(routerCfg, manager); err != nil {
		return fail(errors.New("routing config: ").Base(err))
	}
	var dnsCfg *appdns.Config
	if cfg.DNS != nil {
		dnsCfg, err = cfg.DNS.Build()
		if err != nil {
			return fail(errors.New("build dns config: ").Base(err))
		}
	}
	if err := validateRuntimeConfigWithBuiltDNS(cfg, manager, dnsCfg); err != nil {
		return fail(err)
	}

	var dnsClient featdns.Client
	var routedDNS *appdns.DNS
	if dnsCfg != nil {
		routedDNS, err = appdns.New(ctx, dnsCfg)
		if err != nil {
			return fail(errors.New("create dns server: ").Base(err))
		}
		if err := routedDNS.Start(); err != nil {
			_ = routedDNS.Close()
			return fail(errors.New("start dns server: ").Base(err))
		}
		dnsClient = routedDNS
	} else {
		dnsClient = appdns.NewLocal()
	}

	var observer *observatory.Observer
	if cfg.Observatory != nil && len(cfg.Observatory.SubjectSelector) > 0 {
		observer, err = observatory.New(ctx, cfg.Observatory, manager)
		if err != nil {
			if routedDNS != nil {
				_ = routedDNS.Close()
			}
			return fail(errors.New("build observatory: ").Base(err))
		}
	}

	routerCtx := core.ContextWithFeatures(ctx, dnsClient, manager, nil, observer)
	r := new(router.Router)
	if err := r.Init(routerCtx, routerCfg, dnsClient, manager, nil); err != nil {
		if observer != nil {
			_ = observer.Close()
		}
		if routedDNS != nil {
			_ = routedDNS.Close()
		}
		return fail(errors.New("init router: ").Base(err))
	}
	snapshot := &runtimeSnapshot{
		config: cfg, hash: hash, revision: revision, router: r, outbound: manager,
		dns: dnsClient, routedDNS: routedDNS, observer: observer,
		conns: make(map[*leasedConn]struct{}),
	}
	if routedDNS != nil {
		if runtimeResources && cfg.DNSResultEvents != nil {
			sink, err := dnsevent.New(cfg.DNSResultEvents)
			if err != nil {
				snapshot.closeResources()
				return nil, err
			}
			snapshot.dnsEvents = sink
		}
		if runtimeResources && cfg.DNSResultNFTSets != nil {
			writer, err := dnsnftset.New(cfg.DNSResultNFTSets)
			if err != nil {
				snapshot.closeResources()
				return nil, err
			}
			snapshot.dnsNFTSets = writer
		}
		if runtimeResources {
			routedDNS.SetResultObserver(func(result appdns.Result) {
				sequence := s.dnsEventSequence.Add(1)
				event := dnsevent.NewEvent(result, revision, sequence)
				if snapshot.dnsEvents != nil {
					snapshot.dnsEvents.EmitEvent(event)
				}
				if snapshot.dnsNFTSets != nil {
					snapshot.dnsNFTSets.Emit(result)
				}
				s.recordDNSResult(event)
			})
		}
		routedDNS.SetTaggedDialer(func(dialCtx context.Context, dest bcnet.Destination, tag string) (net.Conn, error) {
			return s.dialDNS(snapshot, dialCtx, dest, tag)
		})
	}
	return snapshot, nil
}

func (s *runtimeService) dialDNS(snapshot *runtimeSnapshot, ctx context.Context, dest bcnet.Destination, forcedTag string) (net.Conn, error) {
	var selected dialer.Dialer
	outboundTag, ruleTag := forcedTag, ""
	usedDefault := false
	if forcedTag != "" {
		selected = snapshot.outbound.GetDialer(forcedTag)
	} else {
		routeContext := &routingsession.Context{
			Inbound:  bcsession.InboundFromContext(ctx),
			Outbound: &bcsession.Outbound{OriginalTarget: dest, Target: dest},
			Content:  bcsession.ContentFromContext(ctx),
		}
		decision, err := snapshot.router.PickRoute(routeContext)
		if err != nil && !stderrors.Is(err, common.ErrNoClue) {
			return nil, err
		}
		if err == nil {
			outboundTag, ruleTag = decision.GetOutboundTag(), decision.GetRuleTag()
			usedDefault = decision.IsFallback()
			selected = snapshot.outbound.GetDialer(outboundTag)
		} else {
			selected = snapshot.outbound.GetDefaultDialer()
			usedDefault = true
		}
	}
	if selected == nil {
		return nil, errors.New("DNS outbound not found: ", outboundTag)
	}
	if outboundTag == "" {
		outboundTag = selected.Tag()
	}
	started := time.Now()
	conn, err := selected.Dial(ctx, dest)
	s.recordOutbound(outboundTag, err)
	result := "success"
	if err != nil {
		result = "error"
	}
	commonmetrics.Inc("bypasscore_outbound_dials_total", "outbound", outboundTag, "network", dest.Network.String(), "result", result)
	commonmetrics.Add("bypasscore_outbound_dial_duration_nanoseconds_total", time.Since(started).Nanoseconds(), "outbound", outboundTag, "network", dest.Network.String())
	if err == nil {
		metricRule := ruleTag
		if metricRule == "" {
			if forcedTag != "" {
				metricRule = "_dns_forced"
			} else if usedDefault {
				metricRule = "_default"
			} else {
				metricRule = "_untagged"
			}
		}
		commonmetrics.Inc("bypasscore_rule_hits_total", "rule", metricRule, "outbound", outboundTag)
	}
	return conn, err
}

func (snapshot *runtimeSnapshot) activate() error {
	if snapshot.observer != nil {
		return snapshot.observer.Start()
	}
	return nil
}

func (s *runtimeService) acquire() (*runtimeSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.current == nil {
		return nil, errors.New("runtime is closed")
	}
	s.current.refs.Add(1)
	return s.current, nil
}

func (snapshot *runtimeSnapshot) release() {
	if snapshot.refs.Add(-1) == 0 && snapshot.retired.Load() {
		go snapshot.closeResources()
	}
}

func (snapshot *runtimeSnapshot) retire() {
	if !snapshot.retired.CompareAndSwap(false, true) {
		return
	}
	if snapshot.refs.Load() == 0 {
		go snapshot.closeResources()
		return
	}
	snapshot.timerMu.Lock()
	if !snapshot.closed.Load() {
		snapshot.drainTimer = time.AfterFunc(runtimeDrainTimeout, snapshot.forceClose)
	}
	snapshot.timerMu.Unlock()
}

func (snapshot *runtimeSnapshot) forceClose() {
	snapshot.connMu.Lock()
	snapshot.forced.Store(true)
	connections := make([]*leasedConn, 0, len(snapshot.conns))
	for conn := range snapshot.conns {
		connections = append(connections, conn)
	}
	snapshot.connMu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	snapshot.closeResources()
}

func (snapshot *runtimeSnapshot) closeResources() {
	snapshot.closeOnce.Do(func() {
		snapshot.closed.Store(true)
		snapshot.timerMu.Lock()
		if snapshot.drainTimer != nil {
			snapshot.drainTimer.Stop()
			snapshot.drainTimer = nil
		}
		snapshot.timerMu.Unlock()
		if snapshot.observer != nil {
			_ = snapshot.observer.Close()
		}
		if snapshot.routedDNS != nil {
			_ = snapshot.routedDNS.Close()
		}
		if snapshot.dnsEvents != nil {
			_ = snapshot.dnsEvents.Close()
		}
		if snapshot.dnsNFTSets != nil {
			_ = snapshot.dnsNFTSets.Close()
		}
		_ = snapshot.router.Close()
		_ = snapshot.outbound.Close()
	})
}

type leasedConn struct {
	net.Conn
	snapshot *runtimeSnapshot
	tag      string
	once     sync.Once
}

func (c *leasedConn) Read(buffer []byte) (int, error) {
	n, err := c.Conn.Read(buffer)
	if n > 0 {
		commonmetrics.Add("bypasscore_outbound_download_bytes_total", int64(n), "outbound", c.tag)
	}
	return n, err
}

func (c *leasedConn) Write(buffer []byte) (int, error) {
	n, err := c.Conn.Write(buffer)
	if n > 0 {
		commonmetrics.Add("bypasscore_outbound_upload_bytes_total", int64(n), "outbound", c.tag)
	}
	return n, err
}

func (c *leasedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Close()
}

func (c *leasedConn) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return nil
}

func (c *leasedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.snapshot.connMu.Lock()
		delete(c.snapshot.conns, c)
		c.snapshot.connMu.Unlock()
		commonmetrics.Add("bypasscore_outbound_active_connections", -1, "outbound", c.tag)
		c.snapshot.release()
	})
	return err
}

func (snapshot *runtimeSnapshot) track(conn net.Conn, tag string) (net.Conn, error) {
	leased := &leasedConn{Conn: conn, snapshot: snapshot, tag: tag}
	snapshot.connMu.Lock()
	if snapshot.forced.Load() {
		snapshot.connMu.Unlock()
		_ = conn.Close()
		snapshot.release()
		return nil, errors.New("runtime snapshot drain timeout exceeded")
	}
	snapshot.conns[leased] = struct{}{}
	snapshot.connMu.Unlock()
	commonmetrics.Inc("bypasscore_outbound_active_connections", "outbound", tag)
	return leased, nil
}

// DialRouted selects and dials while holding one snapshot lease. The lease is
// transferred to the returned connection and released by Close.
func (s *runtimeService) DialRouted(ctx context.Context, routeContext routing.Context, dest bcnet.Destination) (net.Conn, string, string, bool, error) {
	snapshot, err := s.acquire()
	if err != nil {
		return nil, "", "", false, err
	}
	route, routeErr := snapshot.router.PickRoute(routeContext)
	var outboundDialer dialer.Dialer
	var outboundTag, ruleTag string
	usedDefault := false
	if routeErr != nil {
		if !stderrors.Is(routeErr, common.ErrNoClue) {
			snapshot.release()
			return nil, "", "", false, routeErr
		}
		outboundDialer = snapshot.outbound.GetDefaultDialer()
		usedDefault = true
	} else {
		outboundTag, ruleTag = route.GetOutboundTag(), route.GetRuleTag()
		usedDefault = route.IsFallback()
		outboundDialer = snapshot.outbound.GetDialer(outboundTag)
	}
	if outboundDialer == nil {
		snapshot.release()
		return nil, outboundTag, ruleTag, usedDefault, errors.New("no outbound available for route")
	}
	if outboundTag == "" {
		outboundTag = outboundDialer.Tag()
	}
	start := time.Now()
	conn, err := outboundDialer.Dial(ctx, dest)
	s.recordOutbound(outboundTag, err)
	commonmetrics.Add("bypasscore_outbound_dial_duration_nanoseconds_total", time.Since(start).Nanoseconds(), "outbound", outboundTag, "network", dest.Network.String())
	result := "success"
	if err != nil {
		result = "error"
	}
	commonmetrics.Inc("bypasscore_outbound_dials_total", "outbound", outboundTag, "network", dest.Network.String(), "result", result)
	if err != nil {
		snapshot.release()
		return nil, outboundTag, ruleTag, usedDefault, err
	}
	metricRule := ruleTag
	if metricRule == "" {
		if usedDefault {
			metricRule = "_default"
		} else {
			metricRule = "_untagged"
		}
	}
	tracked, err := snapshot.track(conn, outboundTag)
	if err != nil {
		return nil, outboundTag, ruleTag, usedDefault, err
	}
	commonmetrics.Inc("bypasscore_rule_hits_total", "rule", metricRule, "outbound", outboundTag)
	return tracked, outboundTag, ruleTag, usedDefault, nil
}

func (s *runtimeService) PickRoute(ctx routing.Context) (routing.Route, error) {
	snapshot, err := s.acquire()
	if err != nil {
		return nil, err
	}
	defer snapshot.release()
	return snapshot.router.PickRoute(ctx)
}
func (s *runtimeService) GetDialer(tag string) dialer.Dialer {
	return &runtimeDialer{service: s, tag: tag}
}
func (s *runtimeService) GetDefaultDialer() dialer.Dialer { return &runtimeDialer{service: s} }
func (s *runtimeService) Type() interface{}               { return routing.RouterType() }
func (s *runtimeService) Start() error                    { return nil }
func (s *runtimeService) AddRule(message *serial.TypedMessage, append bool) error {
	snapshot, err := s.acquire()
	if err != nil {
		return err
	}
	defer snapshot.release()
	return snapshot.router.AddRule(message, append)
}
func (s *runtimeService) RemoveRule(tag string) error {
	snapshot, err := s.acquire()
	if err != nil {
		return err
	}
	defer snapshot.release()
	return snapshot.router.RemoveRule(tag)
}
func (s *runtimeService) ListRule() []routing.Route {
	snapshot, err := s.acquire()
	if err != nil {
		return nil
	}
	defer snapshot.release()
	return snapshot.router.ListRule()
}

type runtimeDialer struct {
	service *runtimeService
	tag     string
}

func (d *runtimeDialer) Tag() string { return d.tag }
func (d *runtimeDialer) Dial(ctx context.Context, dest bcnet.Destination) (net.Conn, error) {
	snapshot, err := d.service.acquire()
	if err != nil {
		return nil, err
	}
	selected := snapshot.outbound.GetDialer(d.tag)
	if d.tag == "" {
		selected = snapshot.outbound.GetDefaultDialer()
	}
	if selected == nil {
		snapshot.release()
		return nil, errors.New("outbound not found: ", d.tag)
	}
	conn, err := selected.Dial(ctx, dest)
	if err != nil {
		snapshot.release()
		return nil, err
	}
	return snapshot.track(conn, selected.Tag())
}

func (s *runtimeService) LookupIP(domain string, option featdns.IPOption) ([]bcnet.IP, uint32, error) {
	return s.LookupIPContext(context.Background(), domain, option)
}
func (s *runtimeService) LookupIPContext(ctx context.Context, domain string, option featdns.IPOption) ([]bcnet.IP, uint32, error) {
	snapshot, err := s.acquire()
	if err != nil {
		return nil, 0, err
	}
	defer snapshot.release()
	if client, ok := snapshot.dns.(featdns.ContextClient); ok {
		return client.LookupIPContext(ctx, domain, option)
	}
	return snapshot.dns.LookupIP(domain, option)
}
func (s *runtimeService) LookupRawContext(ctx context.Context, domain string, query []byte) ([]byte, error) {
	snapshot, err := s.acquire()
	if err != nil {
		return nil, err
	}
	defer snapshot.release()
	client, ok := snapshot.dns.(featdns.RawContextClient)
	if !ok {
		return nil, errors.New("configured DNS client does not support raw queries")
	}
	return client.LookupRawContext(ctx, domain, query)
}
func (s *runtimeService) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	current := s.current
	s.current = nil
	s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	s.retiredMu.Lock()
	retired := append([]*runtimeSnapshot(nil), s.retired...)
	s.retired = nil
	s.retiredMu.Unlock()
	if current != nil {
		retired = append(retired, current)
	}
	for _, snapshot := range retired {
		snapshot.retire()
		snapshot.forceClose()
	}
	return nil
}

func (s *runtimeService) retireSnapshot(snapshot *runtimeSnapshot) {
	if snapshot == nil {
		return
	}
	snapshot.retire()
	if snapshot.closed.Load() {
		return
	}
	s.retiredMu.Lock()
	kept := s.retired[:0]
	for _, retired := range s.retired {
		if !retired.closed.Load() {
			kept = append(kept, retired)
		}
	}
	s.retired = append(kept, snapshot)
	var victim *runtimeSnapshot
	if len(s.retired) > maxRetiredSnapshots {
		victim = s.retired[0]
		s.retired = s.retired[1:]
	}
	s.retiredMu.Unlock()
	if victim != nil {
		go victim.forceClose()
	}
}

func (s *runtimeService) Status(context.Context) (any, error) {
	snapshot, err := s.acquire()
	if err != nil {
		return nil, err
	}
	defer snapshot.release()
	s.lastReloadMu.RLock()
	reload := s.lastReload
	s.lastReloadMu.RUnlock()
	s.retiredMu.Lock()
	retiredCount := 0
	for _, retired := range s.retired {
		if !retired.closed.Load() {
			retiredCount++
		}
	}
	s.retiredMu.Unlock()
	upstreams := []appdns.UpstreamStatus{}
	if snapshot.routedDNS != nil {
		upstreams = snapshot.routedDNS.UpstreamStatus()
	}
	dnsEventStatus := map[string]any{"enabled": false}
	if snapshot.dnsEvents != nil {
		dnsEventStatus = map[string]any{"enabled": true, "stats": snapshot.dnsEvents.Stats(), "lastSequence": s.dnsEventSequence.Load()}
	}
	dnsNFTSetStatus := dnsnftset.Stats{Enabled: false, Ready: true}
	if snapshot.dnsNFTSets != nil {
		dnsNFTSetStatus = snapshot.dnsNFTSets.Status()
	}
	s.outboundStatusMu.RLock()
	outbounds := make([]outboundRuntimeStatus, 0, len(snapshot.config.Outbounds))
	for _, configured := range snapshot.config.Outbounds {
		status := s.outboundStatus[configured.Tag]
		status.Tag = configured.Tag
		outbounds = append(outbounds, status)
	}
	s.outboundStatusMu.RUnlock()
	health, ready := s.inboundHealth(len(snapshot.config.Inbounds))
	ready = ready && dnsNFTSetStatus.Ready
	inbounds := make([]map[string]any, 0, len(snapshot.config.Inbounds))
	for index, configured := range snapshot.config.Inbounds {
		state := appinbound.HealthStatus{Tag: configured.Tag, State: "starting"}
		if index < len(health) {
			state = health[index]
		}
		inbounds = append(inbounds, map[string]any{"tag": state.Tag, "type": configured.Type, "listen": net.JoinHostPort(configured.Listen, strconv.Itoa(configured.Port)), "state": state.State, "running": state.State == "running", "lastError": state.LastError, "updatedAt": state.UpdatedAt})
	}
	var observation any
	if snapshot.observer != nil {
		observation, _ = snapshot.observer.GetObservation(context.Background())
	}
	return map[string]any{
		"running": true, "ready": ready, "startedAt": s.startedAt,
		"configHash": snapshot.hash, "configRevision": snapshot.revision,
		"activeSnapshotReferences": snapshot.refs.Load() - 1, "retiredSnapshots": retiredCount, "lastReload": reload,
		"geodataLoaded": true, "inbounds": inbounds, "dnsUpstreams": upstreams, "dnsResultEvents": dnsEventStatus, "dnsResultNFTSets": dnsNFTSetStatus, "outbounds": outbounds, "observatory": observation,
	}, nil
}
func (s *runtimeService) Ready(context.Context) (any, error) {
	snapshot, err := s.acquire()
	if err != nil {
		return map[string]any{"ready": false, "checks": map[string]bool{"runtime": false, "inbounds": false, "geodata": false}}, nil
	}
	defer snapshot.release()
	_, inboundsReady := s.inboundHealth(len(snapshot.config.Inbounds))
	nftSetsReady := true
	if snapshot.dnsNFTSets != nil {
		nftSetsReady = snapshot.dnsNFTSets.Status().Ready
	}
	ready := inboundsReady && nftSetsReady
	return map[string]any{
		"ready": ready, "configHash": snapshot.hash, "configRevision": snapshot.revision,
		"checks": map[string]bool{"runtime": true, "inbounds": inboundsReady, "geodata": true, "dnsResultNFTSets": nftSetsReady},
	}, nil
}

func (s *runtimeService) inboundHealth(expected int) ([]appinbound.HealthStatus, bool) {
	s.inboundMu.RLock()
	listeners := append([]reloadableInbound(nil), s.inbounds...)
	s.inboundMu.RUnlock()
	statuses := make([]appinbound.HealthStatus, 0, len(listeners))
	ready := s.listeners.Load() && expected > 0 && len(listeners) == expected
	for _, listener := range listeners {
		status := listener.Status()
		statuses = append(statuses, status)
		if status.State != "running" {
			ready = false
		}
	}
	return statuses, ready
}
func (s *runtimeService) Validate(ctx context.Context, raw []byte) (any, error) {
	cfg, hash, err := s.configFromRequest(raw)
	if err != nil {
		return nil, invalidConfigError(err)
	}
	snapshot, err := s.buildSnapshot(ctx, cfg, 0, hash, false)
	if err != nil {
		return nil, invalidConfigError(err)
	}
	snapshot.closeResources()
	return map[string]any{"valid": true, "configHash": hash}, nil
}
func (s *runtimeService) Reload(ctx context.Context, raw []byte, expectedValues ...string) (any, error) {
	if !s.reloadBusy.CompareAndSwap(false, true) {
		return nil, &control.APIError{Code: "busy", Message: "a configuration reload is already running", Status: http.StatusServiceUnavailable}
	}
	defer s.reloadBusy.Store(false)
	cfg, hash, err := s.configFromRequest(raw)
	if err != nil {
		s.recordReload(err)
		return nil, invalidConfigError(err)
	}
	current, err := s.acquire()
	if err != nil {
		return nil, err
	}
	if len(expectedValues) > 0 {
		expected := strings.Trim(strings.TrimSpace(expectedValues[0]), `"`)
		expected = strings.TrimPrefix(expected, "W/")
		expected = strings.Trim(expected, `"`)
		if expected != "" && expected != strconv.FormatUint(current.revision, 10) && expected != current.hash {
			current.release()
			err := &control.APIError{Code: "revision_conflict", Message: "If-Match does not match the active config revision or hash", Status: http.StatusConflict}
			s.recordReload(err)
			return nil, err
		}
	}
	if hash == current.hash {
		revision := current.revision
		current.release()
		return map[string]any{"reloaded": false, "unchanged": true, "configHash": hash, "configRevision": revision}, nil
	}
	if err := reloadCompatibility(current.config, cfg); err != nil {
		current.release()
		s.recordReload(err)
		return nil, err
	}
	nextRevision := current.revision + 1
	next, err := s.buildSnapshot(s.ctx, cfg, nextRevision, hash, true)
	if err != nil {
		current.release()
		s.recordReload(err)
		return nil, invalidConfigError(err)
	}
	// Startup may intentionally precede supervisor-created sets, but a reload
	// already has a live nftables environment. Validate the candidate writer
	// before changing inbounds or swapping snapshots so failure preserves the
	// complete current runtime transactionally.
	if next.dnsNFTSets != nil {
		if err := next.dnsNFTSets.Probe(); err != nil {
			next.retire()
			current.release()
			s.recordReload(err)
			return nil, &control.APIError{Code: "nftset_unavailable", Message: err.Error(), Status: http.StatusServiceUnavailable}
		}
	}
	if err := s.reloadInbounds(current.config.Inbounds, cfg.Inbounds); err != nil {
		next.retire()
		current.release()
		s.recordReload(err)
		return nil, err
	}
	if s.metrics != nil && cfg.Metrics != nil {
		if err := s.metrics.Reload(cfg.Metrics); err != nil {
			if rollbackErr := s.reloadInbounds(cfg.Inbounds, current.config.Inbounds); rollbackErr != nil {
				err = errors.New("metrics reload failed and inbound rollback failed: ").Base(stderrors.Join(err, rollbackErr))
			}
			next.retire()
			current.release()
			s.recordReload(err)
			return nil, err
		}
	}
	if err := next.activate(); err != nil {
		rollbackErrors := []error{err}
		if rollbackErr := s.reloadInbounds(cfg.Inbounds, current.config.Inbounds); rollbackErr != nil {
			rollbackErrors = append(rollbackErrors, rollbackErr)
		}
		if s.metrics != nil && current.config.Metrics != nil {
			if rollbackErr := s.metrics.Reload(current.config.Metrics); rollbackErr != nil {
				rollbackErrors = append(rollbackErrors, rollbackErr)
			}
		}
		err = stderrors.Join(rollbackErrors...)
		next.retire()
		current.release()
		s.recordReload(err)
		return nil, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		rollbackErrors := []error{errors.New("runtime is closed")}
		if rollbackErr := s.reloadInbounds(cfg.Inbounds, current.config.Inbounds); rollbackErr != nil {
			rollbackErrors = append(rollbackErrors, rollbackErr)
		}
		if s.metrics != nil && current.config.Metrics != nil {
			if rollbackErr := s.metrics.Reload(current.config.Metrics); rollbackErr != nil {
				rollbackErrors = append(rollbackErrors, rollbackErr)
			}
		}
		next.retire()
		current.release()
		return nil, stderrors.Join(rollbackErrors...)
	}
	old := s.current
	s.current = next
	s.mu.Unlock()
	s.pruneMetrics(next)
	s.retireSnapshot(old)
	current.release()
	s.recordReload(nil)
	commonmetrics.Set("bypasscore_config_revision", int64(nextRevision))
	commonmetrics.Inc("bypasscore_config_reloads_total", "result", "success")
	commonmetrics.Set("bypasscore_config_last_reload_timestamp_seconds", time.Now().Unix())
	return map[string]any{"reloaded": true, "configHash": hash, "configRevision": nextRevision}, nil
}

func (s *runtimeService) pruneMetrics(snapshot *runtimeSnapshot) {
	allowed := map[string]map[string]struct{}{
		"outbound": {}, "inbound": {}, "rule": {"_default": {}, "_untagged": {}, "_dns_forced": {}}, "server": {"_default": {}},
	}
	for _, outbound := range snapshot.config.Outbounds {
		allowed["outbound"][outbound.Tag] = struct{}{}
	}
	s.outboundStatusMu.Lock()
	for tag := range s.outboundStatus {
		if _, keep := allowed["outbound"][tag]; !keep {
			delete(s.outboundStatus, tag)
		}
	}
	s.outboundStatusMu.Unlock()
	for _, inbound := range snapshot.config.Inbounds {
		allowed["inbound"][inbound.Tag] = struct{}{}
	}
	for _, route := range snapshot.router.ListRule() {
		if tag := route.GetRuleTag(); tag != "" {
			allowed["rule"][tag] = struct{}{}
		}
	}
	if snapshot.routedDNS != nil {
		for _, status := range snapshot.routedDNS.UpstreamStatus() {
			allowed["server"][status.ServerTag] = struct{}{}
		}
	}
	commonmetrics.RetainLabelValues(allowed)
}

func (s *runtimeService) Explain(_ context.Context, request control.RouteExplainRequest) (any, error) {
	target, err := bcnet.ParseDestination(request.Destination)
	if err != nil {
		return nil, &control.APIError{Code: "invalid_destination", Message: err.Error(), Status: http.StatusBadRequest}
	}
	inbound := &bcsession.Inbound{Tag: request.InboundTag}
	if request.Source != "" {
		source := request.Source
		if !strings.Contains(source, "://") && !strings.HasPrefix(source, "tcp:") && !strings.HasPrefix(source, "udp:") {
			source = "tcp:" + source
		}
		parsed, parseErr := bcnet.ParseDestination(source)
		if parseErr != nil {
			return nil, &control.APIError{Code: "invalid_source", Message: parseErr.Error(), Status: http.StatusBadRequest}
		}
		inbound.Source = parsed
	}
	ctx := &routingsession.Context{Inbound: inbound, Outbound: &bcsession.Outbound{Target: target}, Content: &bcsession.Content{Protocol: request.Protocol}}
	snapshot, err := s.acquire()
	if err != nil {
		return nil, err
	}
	defer snapshot.release()
	decision, err := snapshot.router.PickRoute(ctx)
	if stderrors.Is(err, common.ErrNoClue) {
		fallback := snapshot.outbound.GetDefaultDialer()
		tag := ""
		if fallback != nil {
			tag = fallback.Tag()
		}
		return map[string]any{"matched": false, "default": true, "outboundTag": tag, "configHash": snapshot.hash, "configRevision": snapshot.revision}, nil
	}
	if err != nil {
		return nil, err
	}
	isDefault := decision.IsFallback()
	return map[string]any{"matched": !isDefault && decision.GetRuleTag() != "", "default": isDefault, "ruleTag": decision.GetRuleTag(), "outboundTag": decision.GetOutboundTag(), "configHash": snapshot.hash, "configRevision": snapshot.revision}, nil
}
func (s *runtimeService) Resolve(ctx context.Context, request control.DNSResolveRequest) (any, error) {
	if strings.TrimSpace(request.Domain) == "" {
		return nil, &control.APIError{Code: "invalid_domain", Message: "domain is required", Status: http.StatusBadRequest}
	}
	ipv4, ipv6 := true, true
	if request.IPv4 != nil {
		ipv4 = *request.IPv4
	}
	if request.IPv6 != nil {
		ipv6 = *request.IPv6
	}
	start := time.Now()
	ips, ttl, err := s.LookupIPContext(ctx, request.Domain, featdns.IPOption{IPv4Enable: ipv4, IPv6Enable: ipv6})
	if err != nil {
		return nil, &control.APIError{Code: "dns_error", Message: err.Error(), Status: http.StatusBadGateway}
	}
	values := make([]string, 0, len(ips))
	for _, ip := range ips {
		values = append(values, ip.String())
	}
	return map[string]any{"domain": request.Domain, "ips": values, "ttl": ttl, "latencyMs": time.Since(start).Milliseconds()}, nil
}
func (s *runtimeService) Observatory(context.Context) (any, error) {
	snapshot, err := s.acquire()
	if err != nil {
		return nil, err
	}
	defer snapshot.release()
	if snapshot.observer == nil {
		return map[string]any{"enabled": false, "status": []any{}}, nil
	}
	result, err := snapshot.observer.GetObservation(context.Background())
	if err != nil {
		return nil, err
	}
	return map[string]any{"enabled": true, "status": result}, nil
}
func (s *runtimeService) Metrics(context.Context) (any, error) { return commonmetrics.Snapshot(), nil }
func (s *runtimeService) DNSResults(context.Context) (any, error) {
	snapshot, err := s.acquire()
	if err != nil {
		return nil, err
	}
	defer snapshot.release()
	now := time.Now().Unix()
	s.dnsResultMu.Lock()
	results := make([]dnsevent.Event, 0, len(s.dnsResults))
	for key, event := range s.dnsResults {
		if event.ExpiresAt <= now {
			delete(s.dnsResults, key)
			continue
		}
		results = append(results, event)
	}
	s.dnsResultMu.Unlock()
	sort.Slice(results, func(i, j int) bool { return results[i].Sequence < results[j].Sequence })
	eventStats := dnsevent.Stats{}
	if snapshot.dnsEvents != nil {
		eventStats = snapshot.dnsEvents.Stats()
	}
	return map[string]any{"configRevision": snapshot.revision, "lastSequence": s.dnsEventSequence.Load(), "eventStats": eventStats, "results": results}, nil
}

func (s *runtimeService) DNSNFTSets(context.Context) (any, error) {
	snapshot, err := s.acquire()
	if err != nil {
		return nil, err
	}
	defer snapshot.release()
	if snapshot.dnsNFTSets == nil {
		return dnsnftset.Stats{Enabled: false, Ready: true}, nil
	}
	return snapshot.dnsNFTSets.Status(), nil
}

func (s *runtimeService) ProbeDNSNFTSets(context.Context) (any, error) {
	snapshot, err := s.acquire()
	if err != nil {
		return nil, err
	}
	defer snapshot.release()
	if snapshot.dnsNFTSets == nil {
		return dnsnftset.Stats{Enabled: false, Ready: true}, nil
	}
	if err := snapshot.dnsNFTSets.Probe(); err != nil {
		return nil, &control.APIError{Code: "nftset_unavailable", Message: err.Error(), Status: http.StatusServiceUnavailable}
	}
	return snapshot.dnsNFTSets.Status(), nil
}

func (s *runtimeService) recordDNSResult(event dnsevent.Event) {
	key := strings.ToLower(event.Domain) + "\x00" + event.ServerTag
	s.dnsResultMu.Lock()
	s.dnsResults[key] = event
	if len(s.dnsResults) > 4096 {
		oldestKey := ""
		oldestSequence := ^uint64(0)
		for candidate, value := range s.dnsResults {
			if value.Sequence < oldestSequence {
				oldestKey, oldestSequence = candidate, value.Sequence
			}
		}
		delete(s.dnsResults, oldestKey)
	}
	s.dnsResultMu.Unlock()
}

func (s *runtimeService) configFromRequest(raw []byte) (*Config, string, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return loadConfigAndHash(s.configPath)
	}
	return decodeConfig(raw)
}
func (s *runtimeService) recordReload(err error) {
	status := reloadStatus{Success: err == nil, At: time.Now()}
	if err != nil {
		status.Error = err.Error()
		commonmetrics.Inc("bypasscore_config_reloads_total", "result", "error")
	}
	s.lastReloadMu.Lock()
	s.lastReload = status
	s.lastReloadMu.Unlock()
}

func (s *runtimeService) recordOutbound(tag string, err error) {
	s.mu.RLock()
	current := s.current
	allowed := current != nil && current.outbound.GetOutbound(tag) != nil
	s.mu.RUnlock()
	if !allowed {
		return
	}
	now := time.Now()
	s.outboundStatusMu.Lock()
	status := s.outboundStatus[tag]
	status.Tag = tag
	if err == nil {
		status.LastSuccess = now
		status.LastError = ""
	} else {
		status.LastFailure = now
		status.LastError = err.Error()
	}
	s.outboundStatus[tag] = status
	s.outboundStatusMu.Unlock()
}

func invalidConfigError(err error) error {
	return &control.APIError{Code: "invalid_config", Message: err.Error(), Status: http.StatusBadRequest}
}

func reloadCompatibility(current, next *Config) error {
	if len(current.Inbounds) != len(next.Inbounds) {
		return &control.APIError{Code: "restart_required", Message: "adding or removing inbound listeners requires restart", Status: http.StatusConflict}
	}
	for index := range current.Inbounds {
		if current.Inbounds[index].Tag != next.Inbounds[index].Tag {
			return &control.APIError{Code: "restart_required", Message: "inbound tag changes require restart", Status: http.StatusConflict}
		}
		if !sameInboundBinding(current.Inbounds[index], next.Inbounds[index]) {
			return &control.APIError{Code: "restart_required", Message: "inbound listen identity changed", Status: http.StatusConflict}
		}
		left, right := current.Inbounds[index], next.Inbounds[index]
		if left.Sniffing != right.Sniffing || left.SniffingTimeoutMs != right.SniffingTimeoutMs || left.SniffingMaxBytes != right.SniffingMaxBytes || !reflect.DeepEqual(left.DNSRules, right.DNSRules) {
			return &control.APIError{Code: "restart_required", Message: "routing-affecting inbound sniffing or DNS rule changes require restart", Status: http.StatusConflict}
		}
	}
	if (current.Metrics == nil) != (next.Metrics == nil) || metricsListen(current.Metrics) != metricsListen(next.Metrics) {
		return &control.APIError{Code: "restart_required", Message: "metrics listener changes require restart", Status: http.StatusConflict}
	}
	if !control.EquivalentConfig(current.Control, next.Control) {
		return &control.APIError{Code: "restart_required", Message: "control listener changes require restart", Status: http.StatusConflict}
	}
	return nil
}

func sameInboundBinding(left, right *appinbound.Config) bool {
	if left == nil || right == nil {
		return left == right
	}
	return appinbound.SameListenerBinding(left, right) &&
		left.DNSCertificateFile == right.DNSCertificateFile && left.DNSKeyFile == right.DNSKeyFile && appinbound.EffectiveDNSDoHPath(left) == appinbound.EffectiveDNSDoHPath(right)
}

func metricsListen(config *appmetrics.Config) string {
	if config == nil {
		return ""
	}
	value := strings.TrimSpace(config.Listen)
	if value == "" {
		return "127.0.0.1:9090"
	}
	return value
}

func (s *runtimeService) registerInbound(inbound reloadableInbound) {
	s.inboundMu.Lock()
	s.inbounds = append(s.inbounds, inbound)
	s.inboundMu.Unlock()
}

func (s *runtimeService) reloadInbounds(previous, next []*appinbound.Config) error {
	s.inboundMu.RLock()
	listeners := append([]reloadableInbound(nil), s.inbounds...)
	s.inboundMu.RUnlock()
	if len(listeners) != len(next) {
		return &control.APIError{Code: "restart_required", Message: "inbound listener set changed", Status: http.StatusConflict}
	}
	commits := make([]func() error, len(next))
	for index, config := range next {
		listener := listeners[index]
		if listener == nil {
			return &control.APIError{Code: "restart_required", Message: "inbound listener set changed", Status: http.StatusConflict}
		}
		commit, err := listener.PrepareReload(config)
		if err != nil {
			return &control.APIError{Code: "reload_failed", Message: err.Error(), Status: http.StatusInternalServerError}
		}
		commits[index] = commit
	}
	for index, commit := range commits {
		if err := commit(); err != nil {
			rollbackErrors := []error{err}
			for rollbackIndex := 0; rollbackIndex < index; rollbackIndex++ {
				if rollbackErr := listeners[rollbackIndex].Reload(previous[rollbackIndex]); rollbackErr != nil {
					rollbackErrors = append(rollbackErrors, rollbackErr)
				}
			}
			return &control.APIError{Code: "reload_failed", Message: stderrors.Join(rollbackErrors...).Error(), Status: http.StatusInternalServerError}
		}
	}
	return nil
}

func loadConfigAndHash(path string) (*Config, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(raw) > maxConfigBytes {
		return nil, "", errors.New("config exceeds 16 MiB")
	}
	return decodeConfig(raw)
}
func decodeConfig(raw []byte) (*Config, string, error) {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, "", errors.New("parse config.json").Base(err)
	}
	var cfg Config
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, "", errors.New("parse config.json").Base(err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, "", errors.New("parse config.json: multiple JSON values")
		}
		return nil, "", err
	}
	var canonical any
	canonicalDecoder := json.NewDecoder(strings.NewReader(string(raw)))
	canonicalDecoder.UseNumber()
	if err := canonicalDecoder.Decode(&canonical); err != nil {
		return nil, "", err
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(encoded)
	return &cfg, hex.EncodeToString(sum[:]), nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var walk func(string) error
	walk = func(path string) error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON object key")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate JSON key at ", path, ".", key)
				}
				seen[key] = struct{}{}
				if err := walk(path + "." + key); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil {
				return err
			}
			if closing != json.Delim('}') {
				return errors.New("invalid JSON object")
			}
		case '[':
			index := 0
			for decoder.More() {
				if err := walk(path + "[" + strconv.Itoa(index) + "]"); err != nil {
					return err
				}
				index++
			}
			closing, err := decoder.Token()
			if err != nil {
				return err
			}
			if closing != json.Delim(']') {
				return errors.New("invalid JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk("$"); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
