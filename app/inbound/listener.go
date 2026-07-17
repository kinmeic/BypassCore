package inbound

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eugene/bypasscore/app/dispatcher"
	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/common/session"
)

// Listener is a transparent proxy listener supporting both TCP (redirect/tproxy)
// and UDP (tproxy). The network config field determines which protocols to listen on.
type Listener struct {
	cfg         *Config
	dispatcher  *dispatcher.Dispatcher
	inboundType string

	tcpListener net.Listener
	udpListener *udpTproxyListener
	wg          sync.WaitGroup

	// activeConns tracks accepted TCP connections so Close() can force-close
	// them, unblocking handleConn→Dispatch→Bridge goroutines that would
	// otherwise block wg.Wait() forever.
	connMu      sync.Mutex
	activeConns map[net.Conn]struct{}

	ctx        context.Context
	cancel     context.CancelFunc
	stateMu    sync.Mutex
	state      listenerState
	runtimeTag atomic.Pointer[string]
	health     *healthTracker
}

type listenerState uint8

const (
	listenerNew listenerState = iota
	listenerStarting
	listenerRunning
	listenerClosed
)

// New creates a Listener.
func New(cfg *Config, d *dispatcher.Dispatcher) *Listener {
	l := &Listener{
		cfg:         cfg,
		dispatcher:  d,
		activeConns: make(map[net.Conn]struct{}),
	}
	tag := ""
	if cfg != nil {
		l.setTag(cfg.Tag)
		tag = cfg.Tag
	}
	l.health = newHealthTracker(tag)
	return l
}

func (l *Listener) Status() HealthStatus   { return l.health.snapshot() }
func (l *Listener) Failures() <-chan error { return l.health.failures }

func (l *Listener) setTag(tag string) { value := tag; l.runtimeTag.Store(&value) }
func (l *Listener) inboundTag() string {
	if value := l.runtimeTag.Load(); value != nil {
		return *value
	}
	return ""
}

// Reload applies parameters that do not require rebinding the transparent
// sockets. Existing flows keep their current resources; new flows use the new
// sniffing and UDP limits.
func (l *Listener) Reload(cfg *Config) error {
	commit, err := l.PrepareReload(cfg)
	if err != nil {
		return err
	}
	return commit()
}

// PrepareReload validates and allocates all mutable policy objects without
// changing live traffic. The returned commit only publishes prepared values.
func (l *Listener) PrepareReload(cfg *Config) (func() error, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	l.stateMu.Lock()
	if l.state != listenerRunning {
		l.stateMu.Unlock()
		return nil, errors.New("inbound: listener is not running")
	}
	if !SameListenerBinding(l.cfg, cfg) {
		l.stateMu.Unlock()
		return nil, errors.New("inbound: listen identity changed")
	}
	if l.cfg.Tag != cfg.Tag {
		l.stateMu.Unlock()
		return nil, errors.New("inbound: tag changes require restart")
	}
	hasUDP := l.udpListener != nil
	l.stateMu.Unlock()
	sniffer, err := dispatcher.NewSnifferWithOptions(cfg.Sniffing, cfg.SniffingTimeoutMs, cfg.SniffingMaxBytes)
	if err != nil {
		return nil, err
	}
	var limits udpResourceLimits
	if hasUDP {
		limits, err = udpResourceLimitsFromConfig(cfg)
		if err != nil {
			return nil, err
		}
	}
	return func() error {
		l.stateMu.Lock()
		defer l.stateMu.Unlock()
		if l.state != listenerRunning || !SameListenerBinding(l.cfg, cfg) || l.cfg.Tag != cfg.Tag {
			return errors.New("inbound: listener changed after reload preparation")
		}
		l.dispatcher.SetSniffer(sniffer)
		if l.udpListener != nil {
			l.udpListener.setLimits(limits)
		}
		l.cfg = cfg
		return nil
	}, nil
}

// SameListenerBinding reports whether two configs use the same kernel sockets.
func SameListenerBinding(left, right *Config) bool {
	if left == nil || right == nil {
		return left == right
	}
	return normalizedInboundType(left.Type) == normalizedInboundType(right.Type) &&
		normalizedInboundListen(left) == normalizedInboundListen(right) && left.Port == right.Port &&
		normalizedInboundNetwork(left) == normalizedInboundNetwork(right)
}

func normalizedInboundListen(cfg *Config) string {
	value := strings.Trim(strings.TrimSpace(cfg.Listen), "[]")
	if value == "" {
		typ := normalizedInboundType(cfg.Type)
		if typ == "dns" || typ == "dot" || typ == "doh" {
			return "127.0.0.1"
		}
	}
	return value
}

func normalizedInboundType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "redirect"
	}
	return value
}

func normalizedInboundNetwork(config *Config) string {
	value := strings.TrimSpace(config.Network)
	if value == "" {
		typeName := normalizedInboundType(config.Type)
		if typeName == "dns" {
			return "tcp,udp"
		}
		return "tcp"
	}
	tcp, udp, err := parseInboundNetworks(value)
	if err != nil {
		return strings.ToLower(value)
	}
	if tcp && udp {
		return "tcp,udp"
	}
	if udp {
		return "udp"
	}
	return "tcp"
}

// EffectiveDNSDoHPath returns the listener path after applying its default.
func EffectiveDNSDoHPath(config *Config) string {
	if config == nil {
		return ""
	}
	path := strings.TrimSpace(config.DNSDoHPath)
	if path == "" {
		return "/dns-query"
	}
	return path
}

// Start begins listening on TCP and/or UDP based on the network config.
func (l *Listener) Start() error {
	l.stateMu.Lock()
	defer l.stateMu.Unlock()
	switch l.state {
	case listenerStarting, listenerRunning:
		return errors.New("inbound: listener is already started")
	case listenerClosed:
		return errors.New("inbound: listener is closed")
	}
	l.state = listenerStarting
	l.health.set(l.inboundTag(), "starting", nil, false)
	if err := l.startLocked(); err != nil {
		l.closeResourcesLocked()
		l.state = listenerNew
		l.health.set(l.inboundTag(), "failed", err, false)
		return err
	}
	l.state = listenerRunning
	l.health.set(l.inboundTag(), "running", nil, false)
	return nil
}

func (l *Listener) startLocked() error {
	if l.cfg == nil {
		return errors.New("inbound: nil configuration")
	}
	if l.dispatcher == nil {
		return errors.New("inbound: dispatcher is unavailable")
	}
	l.ctx, l.cancel = context.WithCancel(context.Background())
	l.connMu.Lock()
	l.activeConns = make(map[net.Conn]struct{})
	l.connMu.Unlock()
	typeCfg := strings.ToLower(strings.TrimSpace(l.cfg.Type))
	if typeCfg == "" {
		typeCfg = "redirect"
	}
	if typeCfg != "redirect" && typeCfg != "tproxy" {
		return errors.New("inbound: type must be redirect or tproxy")
	}
	// Keep normalized runtime state separate from the source configuration.
	// The latter is compared during SIGHUP reload and must remain immutable.
	l.inboundType = typeCfg

	if l.cfg.Port < 1 || l.cfg.Port > 65535 {
		return errors.New("inbound: port must be between 1 and 65535")
	}
	wantTCP, wantUDP, err := parseInboundNetworks(l.cfg.Network)
	if err != nil {
		return err
	}
	if wantUDP && typeCfg != "tproxy" {
		return errors.New("inbound: UDP requires type=tproxy")
	}

	if wantTCP {
		addr := net.JoinHostPort(normalizedInboundListen(l.cfg), strconv.Itoa(l.cfg.Port))
		ln, err := listenTCP(l.cfg, addr)
		if err != nil {
			return errors.New("inbound TCP listen failed: ", addr).Base(err)
		}
		l.tcpListener = ln
		errors.LogInfo(context.Background(), "inbound[", l.inboundTag(), "] listening on tcp://", addr)
		l.wg.Add(1)
		go l.acceptLoop()
	}

	if wantUDP {
		udpLn, err := startUDP(l.cfg, l.dispatcher, func(state string, err error) {
			l.health.setComponent(l.inboundTag(), "udp", state, err, state == "failed")
		})
		if err != nil {
			return errors.New("inbound UDP listen failed").Base(err)
		}
		l.udpListener = udpLn
	}

	if !wantTCP && !wantUDP {
		return errors.New("inbound: network must be tcp, udp, or tcp,udp")
	}

	return nil
}

func parseInboundNetworks(value string) (bool, bool, error) {
	if strings.TrimSpace(value) == "" {
		return true, false, nil
	}
	var tcp, udp bool
	for _, item := range strings.Split(strings.ToLower(value), ",") {
		switch strings.TrimSpace(item) {
		case "tcp":
			tcp = true
		case "udp":
			udp = true
		default:
			return false, false, errors.New("inbound: network must contain only tcp and/or udp")
		}
	}
	return tcp, udp, nil
}

// Close stops all listeners and force-closes active connections so that
// blocked handleConn goroutines unblock and wg.Wait() returns promptly.
func (l *Listener) Close() error {
	l.stateMu.Lock()
	defer l.stateMu.Unlock()
	if l.state == listenerClosed {
		return nil
	}
	l.state = listenerClosed
	l.closeResourcesLocked()
	l.health.set(l.inboundTag(), "closed", nil, false)
	return nil
}

func (l *Listener) closeResourcesLocked() {
	if l.cancel != nil {
		l.cancel()
	}
	if l.tcpListener != nil {
		_ = l.tcpListener.Close()
	}
	if l.udpListener != nil {
		_ = l.udpListener.Close()
	}
	// Force-close all active connections so Dispatch→Bridge goroutines
	// unblock (io.Copy returns when a conn is closed).
	l.connMu.Lock()
	for conn := range l.activeConns {
		_ = conn.Close()
	}
	l.activeConns = nil // prevent further tracking
	l.connMu.Unlock()
	l.wg.Wait()
	l.tcpListener = nil
	l.udpListener = nil
	l.ctx = nil
	l.cancel = nil
}

// acceptLoop accepts TCP connections and dispatches them.
func (l *Listener) acceptLoop() {
	defer l.wg.Done()
	degraded := false
	for {
		conn, err := l.tcpListener.Accept()
		if err != nil {
			if l.ctx.Err() != nil {
				return
			}
			errors.LogErrorInner(context.Background(), err, "inbound accept failed")
			if !isRetryableNetworkError(err) {
				l.health.setComponent(l.inboundTag(), "tcp", "failed", err, true)
				return
			}
			l.health.setComponent(l.inboundTag(), "tcp", "degraded", err, false)
			degraded = true
			// Back off on persistent errors (e.g. EMFILE) to avoid burning CPU.
			select {
			case <-l.ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		if degraded {
			l.health.setComponent(l.inboundTag(), "tcp", "running", nil, false)
			degraded = false
		}
		l.wg.Add(1)
		go l.handleConn(conn)
	}
}

// handleConn recovers the original destination and dispatches.
func (l *Listener) handleConn(conn net.Conn) {
	defer l.wg.Done()

	// Track the connection so Close() can force-close it to unblock Bridge.
	l.connMu.Lock()
	if l.activeConns != nil {
		l.activeConns[conn] = struct{}{}
		defer func() {
			l.connMu.Lock()
			delete(l.activeConns, conn)
			l.connMu.Unlock()
		}()
	}
	l.connMu.Unlock()

	var dest bcnet.Destination
	var err error
	if l.inboundType == "tproxy" {
		// As in Xray, a transparent TCP socket exposes the intercepted target as
		// the accepted connection's local address.
		dest = bcnet.DestinationFromAddr(conn.LocalAddr())
	} else {
		dest, err = getOriginalDst(conn)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "inbound failed to get original dest")
			conn.Close()
			return
		}
	}

	ctx := session.ContextWithInbound(l.ctx, &session.Inbound{
		Source: bcnet.DestinationFromAddr(conn.RemoteAddr()),
		Local:  bcnet.DestinationFromAddr(conn.LocalAddr()),
		Tag:    l.inboundTag(),
	})
	ctx = session.ContextWithContent(ctx, new(session.Content))

	// Dispatch blocks until the connection is fully proxied.
	if err := l.dispatcher.Dispatch(ctx, conn, dest); err != nil {
		errors.LogErrorInner(context.Background(), err, "inbound dispatch failed for ", dest.String())
	}
}
