package inbound

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	goerrors "errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	commonmetrics "github.com/eugene/bypasscore/common/metrics"
	dnsfeature "github.com/eugene/bypasscore/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	defaultDNSMaxConcurrentQueries = 256
	defaultDNSMaxTCPConnections    = 128
	defaultDNSMaxQueryBytes        = 4096
	dnsTCPIdleTimeout              = 30 * time.Second
	maxDNSUDPPayload               = 4096
	maxDNSMessageSize              = 65535
	maxDNSConfiguredLimit          = 65535
	maxDoHConcurrentStreams        = 1024
	rcodeBadVersion                = dnsmessage.RCode(16)
)

type dnsListenerState uint8

const (
	dnsListenerNew dnsListenerState = iota
	dnsListenerStarting
	dnsListenerRunning
	dnsListenerClosed
)

// DNSListener exposes the internal DNS client as a conventional UDP/TCP DNS
// service. It is the native equivalent of Xray's dokodemo-door + dns outbound
// combination, without routing DNS packets through a synthetic proxy link.
type DNSListener struct {
	cfg    *Config
	client dnsfeature.Client

	ctx        context.Context
	cancel     context.CancelFunc
	tcp        net.Listener
	udp        *net.UDPConn
	httpServer *http.Server

	querySlots     chan struct{}
	tcpSlots       chan struct{}
	queryBytes     int
	allowedClients []netip.Prefix
	rateLimiter    *dnsRateLimiter
	globalLimiter  *dnsGlobalRateLimiter
	dnsRules       []compiledDNSRule
	rawCache       *dnsRawCache
	policyMu       sync.RWMutex
	wg             sync.WaitGroup

	stateMu    sync.Mutex
	state      dnsListenerState
	connMu     sync.Mutex
	conns      map[net.Conn]struct{}
	dohConns   map[net.Conn]dohConnLease
	runtimeTag atomic.Pointer[string]
	health     *healthTracker
}

// NewDNS creates a normal (non-transparent) DNS listener.
func NewDNS(cfg *Config, client dnsfeature.Client) *DNSListener {
	l := &DNSListener{cfg: cfg, client: client, conns: make(map[net.Conn]struct{})}
	tag := ""
	if cfg != nil {
		l.setTag(cfg.Tag)
		tag = cfg.Tag
	}
	l.health = newHealthTracker(tag)
	return l
}

func (l *DNSListener) Status() HealthStatus   { return l.health.snapshot() }
func (l *DNSListener) Failures() <-chan error { return l.health.failures }

func (l *DNSListener) setTag(tag string) { value := tag; l.runtimeTag.Store(&value) }
func (l *DNSListener) inboundTag() string {
	if value := l.runtimeTag.Load(); value != nil {
		return *value
	}
	return ""
}

type dnsRuntimePolicy struct {
	querySlots     chan struct{}
	tcpSlots       chan struct{}
	queryBytes     int
	allowedClients []netip.Prefix
	rateLimiter    *dnsRateLimiter
	globalLimiter  *dnsGlobalRateLimiter
	dnsRules       []compiledDNSRule
	rawCache       *dnsRawCache
}

func buildDNSRuntimePolicy(cfg *Config) (*dnsRuntimePolicy, error) {
	maxQueries, err := positiveLimit(cfg.MaxConcurrentQueries, defaultDNSMaxConcurrentQueries, "maxConcurrentQueries")
	if err != nil {
		return nil, err
	}
	maxQueryBytes, err := queryByteLimit(cfg.MaxQueryBytes)
	if err != nil {
		return nil, err
	}
	maxTCP, err := positiveLimit(cfg.MaxTCPConnections, defaultDNSMaxTCPConnections, "maxTCPConnections")
	if err != nil {
		return nil, err
	}
	allowedClients, rateLimiter, globalLimiter, err := newDNSAccessPolicy(cfg)
	if err != nil {
		return nil, err
	}
	dnsRules, err := compileDNSRules(cfg.DNSRules)
	if err != nil {
		return nil, err
	}
	rawCache, err := newDNSRawCacheWithLimit(cfg.DNSRawCacheEntries, cfg.DNSRawCacheMaxTTLSeconds, cfg.DNSRawCacheMaxBytes)
	if err != nil {
		return nil, err
	}
	return &dnsRuntimePolicy{
		querySlots: make(chan struct{}, maxQueries), tcpSlots: make(chan struct{}, maxTCP), queryBytes: maxQueryBytes,
		allowedClients: allowedClients, rateLimiter: rateLimiter, globalLimiter: globalLimiter, dnsRules: dnsRules, rawCache: rawCache,
	}, nil
}

func (l *DNSListener) currentPolicy() dnsRuntimePolicy {
	l.policyMu.RLock()
	defer l.policyMu.RUnlock()
	return dnsRuntimePolicy{l.querySlots, l.tcpSlots, l.queryBytes, l.allowedClients, l.rateLimiter, l.globalLimiter, l.dnsRules, l.rawCache}
}

func (l *DNSListener) installPolicy(policy *dnsRuntimePolicy) {
	l.policyMu.Lock()
	l.querySlots, l.tcpSlots, l.queryBytes = policy.querySlots, policy.tcpSlots, policy.queryBytes
	l.allowedClients, l.rateLimiter, l.globalLimiter = policy.allowedClients, policy.rateLimiter, policy.globalLimiter
	l.dnsRules, l.rawCache = policy.dnsRules, policy.rawCache
	l.policyMu.Unlock()
}

// Reload atomically replaces DNS policy and resource limits when the socket
// identity is unchanged. Existing TCP sessions retain their connection slot;
// each new query observes the latest policy.
func (l *DNSListener) Reload(cfg *Config) error {
	commit, err := l.PrepareReload(cfg)
	if err != nil {
		return err
	}
	return commit()
}

func (l *DNSListener) PrepareReload(cfg *Config) (func() error, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	l.stateMu.Lock()
	if l.state != dnsListenerRunning {
		l.stateMu.Unlock()
		return nil, errors.New("DNS inbound: listener is not running")
	}
	if !SameListenerBinding(l.cfg, cfg) || l.cfg.DNSCertificateFile != cfg.DNSCertificateFile ||
		l.cfg.DNSKeyFile != cfg.DNSKeyFile || EffectiveDNSDoHPath(l.cfg) != EffectiveDNSDoHPath(cfg) {
		l.stateMu.Unlock()
		return nil, errors.New("DNS inbound: listen identity changed")
	}
	if l.cfg.Tag != cfg.Tag {
		l.stateMu.Unlock()
		return nil, errors.New("DNS inbound: tag changes require restart")
	}
	l.stateMu.Unlock()
	policy, err := buildDNSRuntimePolicy(cfg)
	if err != nil {
		return nil, err
	}
	return func() error {
		l.stateMu.Lock()
		defer l.stateMu.Unlock()
		if l.state != dnsListenerRunning || !SameListenerBinding(l.cfg, cfg) || l.cfg.Tag != cfg.Tag {
			return errors.New("DNS inbound: listener changed after reload preparation")
		}
		l.installPolicy(policy)
		l.cfg = cfg
		return nil
	}, nil
}

// Start binds all configured DNS transports.
func (l *DNSListener) Start() error {
	l.stateMu.Lock()
	defer l.stateMu.Unlock()
	switch l.state {
	case dnsListenerRunning, dnsListenerStarting:
		return errors.New("DNS inbound: listener is already started")
	case dnsListenerClosed:
		return errors.New("DNS inbound: listener is closed")
	}
	l.state = dnsListenerStarting
	l.health.set(l.inboundTag(), "starting", nil, false)
	if err := l.startLocked(); err != nil {
		l.closeResourcesLocked()
		l.state = dnsListenerNew
		l.health.set(l.inboundTag(), "failed", err, false)
		return err
	}
	l.state = dnsListenerRunning
	l.health.set(l.inboundTag(), "running", nil, false)
	return nil
}

func (l *DNSListener) startLocked() error {
	if l.cfg == nil {
		return errors.New("DNS inbound: nil configuration")
	}
	listenerType := strings.ToLower(strings.TrimSpace(l.cfg.Type))
	if listenerType != "dns" && listenerType != "dot" && listenerType != "doh" {
		return errors.New("DNS inbound: type must be dns, dot, or doh")
	}
	if listenerType == "doh" && l.cfg.MaxConcurrentQueries > maxDoHConcurrentStreams {
		return errors.New("DNS inbound: DoH maxConcurrentQueries must not exceed ", maxDoHConcurrentStreams)
	}
	if l.client == nil {
		return errors.New("DNS inbound: DNS client is unavailable")
	}
	if l.cfg.Port < 1 || l.cfg.Port > 65535 {
		return errors.New("DNS inbound: port must be between 1 and 65535")
	}
	policy, err := buildDNSRuntimePolicy(l.cfg)
	if err != nil {
		return err
	}

	network := strings.TrimSpace(l.cfg.Network)
	if network == "" {
		if listenerType == "dns" {
			network = "tcp,udp"
		} else {
			network = "tcp"
		}
	}
	wantTCP, wantUDP, err := parseInboundNetworks(network)
	if err != nil {
		return errors.New("DNS inbound: invalid network").Base(err)
	}
	if !wantTCP && !wantUDP {
		return errors.New("DNS inbound: network must enable TCP and/or UDP")
	}
	if listenerType != "dns" && (!wantTCP || wantUDP) {
		return errors.New("DNS inbound: dot/doh require network=tcp")
	}
	var serverTLS *tls.Config
	if listenerType == "dot" || listenerType == "doh" {
		serverTLS, err = loadDNSServerTLSConfig(l.cfg)
		if err != nil {
			return err
		}
	}

	l.ctx, l.cancel = context.WithCancel(context.Background())
	l.installPolicy(policy)
	l.connMu.Lock()
	l.conns = make(map[net.Conn]struct{})
	l.dohConns = make(map[net.Conn]dohConnLease)
	l.connMu.Unlock()
	listenHost := normalizedInboundListen(l.cfg)
	if ip := net.ParseIP(strings.Trim(listenHost, "[]")); ip != nil && !ip.IsLoopback() && len(policy.allowedClients) == 0 {
		errors.LogWarning(context.Background(), "DNS inbound[", l.inboundTag(), "] is non-loopback without dnsAllowedClients")
	}
	addr := net.JoinHostPort(listenHost, strconv.Itoa(l.cfg.Port))
	if listenerType == "doh" {
		return l.startDoH(addr, serverTLS)
	}

	if wantTCP {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return errors.New("DNS inbound TCP listen failed: ", addr).Base(err)
		}
		if listenerType == "dot" {
			ln = tls.NewListener(ln, serverTLS)
		}
		l.tcp = ln
		scheme := "dns+tcp://"
		if listenerType == "dot" {
			scheme = "dot://"
		}
		errors.LogInfo(context.Background(), "inbound[", l.inboundTag(), "] listening on ", scheme, addr)
		l.wg.Add(1)
		go l.acceptTCP()
	}

	if wantUDP {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return errors.New("DNS inbound UDP address failed: ", addr).Base(err)
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return errors.New("DNS inbound UDP listen failed: ", addr).Base(err)
		}
		l.udp = conn
		errors.LogInfo(context.Background(), "inbound[", l.inboundTag(), "] listening on dns+udp://", addr)
		l.wg.Add(1)
		go l.serveUDP()
	}

	return nil
}

func positiveLimit(value, fallback int, field string) (int, error) {
	if value < 0 || value > maxDNSConfiguredLimit {
		return 0, errors.New("DNS inbound: ", field, " must be between 0 and ", maxDNSConfiguredLimit)
	}
	if value == 0 {
		return fallback, nil
	}
	return value, nil
}

func queryByteLimit(value int) (int, error) {
	if value == 0 {
		return defaultDNSMaxQueryBytes, nil
	}
	if value < 512 || value > maxDNSMessageSize {
		return 0, errors.New("DNS inbound: maxQueryBytes must be between 512 and ", maxDNSMessageSize)
	}
	return value, nil
}

// Close stops listeners, closes active TCP clients, and waits for handlers.
func (l *DNSListener) Close() error {
	l.stateMu.Lock()
	defer l.stateMu.Unlock()
	if l.state == dnsListenerClosed {
		return nil
	}
	if l.state == dnsListenerNew {
		l.state = dnsListenerClosed
		l.health.set(l.inboundTag(), "closed", nil, false)
		return nil
	}
	l.state = dnsListenerClosed
	l.closeResourcesLocked()
	l.health.set(l.inboundTag(), "closed", nil, false)
	return nil
}

func (l *DNSListener) closeResourcesLocked() {
	if l.cancel != nil {
		l.cancel()
	}
	if l.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := l.httpServer.Shutdown(ctx); err != nil {
			_ = l.httpServer.Close()
		}
		cancel()
	}
	if l.tcp != nil {
		_ = l.tcp.Close()
	}
	if l.udp != nil {
		_ = l.udp.Close()
	}
	l.connMu.Lock()
	for conn := range l.conns {
		_ = conn.Close()
	}
	for _, lease := range l.dohConns {
		<-lease.slots
		commonmetrics.Add("bypasscore_dns_tcp_connections_active", -1, "inbound", lease.tag)
	}
	l.conns = nil
	l.dohConns = nil
	l.connMu.Unlock()
	l.wg.Wait()
	l.tcp = nil
	l.udp = nil
	l.httpServer = nil
	l.ctx = nil
	l.cancel = nil
	l.policyMu.Lock()
	l.querySlots, l.tcpSlots, l.allowedClients = nil, nil, nil
	l.rateLimiter, l.globalLimiter, l.dnsRules, l.rawCache = nil, nil, nil, nil
	l.policyMu.Unlock()
}

func (l *DNSListener) serveUDP() {
	defer l.wg.Done()
	buf := make([]byte, maxDNSMessageSize+1)
	degraded := false
	for {
		n, peer, err := l.udp.ReadFromUDP(buf)
		if err != nil {
			if l.ctx.Err() != nil {
				return
			}
			errors.LogErrorInner(context.Background(), err, "DNS inbound UDP read failed")
			if !isRetryableNetworkError(err) {
				l.health.setComponent(l.inboundTag(), "udp", "failed", err, true)
				return
			}
			l.health.setComponent(l.inboundTag(), "udp", "degraded", err, false)
			degraded = true
			select {
			case <-l.ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		if degraded {
			l.health.setComponent(l.inboundTag(), "udp", "running", nil, false)
			degraded = false
		}
		policy := l.currentPolicy()
		if n > policy.queryBytes {
			continue
		}
		peerIP, ok := clientIP(peer)
		if !ok || !clientAllowed(peerIP, policy.allowedClients) {
			commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.inboundTag(), "reason", "acl", "transport", "udp")
			continue
		}
		now := time.Now()
		if !policy.rateLimiter.allow(peerIP, now) || !policy.globalLimiter.allow(now) {
			// Drop unauthorized/rate-limited UDP silently. Replying would let a
			// spoofed source turn the listener into a reflection endpoint.
			commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.inboundTag(), "reason", "rate", "transport", "udp")
			continue
		}
		commonmetrics.Inc("bypasscore_dns_queries_total", "inbound", l.inboundTag(), "transport", "udp")
		select {
		case policy.querySlots <- struct{}{}:
			request := append([]byte(nil), buf[:n]...)
			querySlots := policy.querySlots
			l.wg.Add(1)
			go func() {
				defer l.wg.Done()
				defer func() { <-querySlots }()
				response, err := l.handleQuery(request, true)
				if err != nil {
					errors.LogErrorInner(context.Background(), err, "DNS inbound UDP query failed")
					return
				}
				if len(response) > 0 {
					l.recordDNSResponse(response, "udp")
					if _, err := l.udp.WriteToUDP(response, peer); err != nil && l.ctx.Err() == nil {
						errors.LogErrorInner(context.Background(), err, "DNS inbound UDP response failed")
					}
				}
			}()
		default:
			// Shed overload with an explicit SERVFAIL instead of allocating an
			// unbounded number of goroutines or silently timing out the client.
			response := errorResponse(buf[:n], dnsmessage.RCodeServerFailure)
			if len(response) > 0 {
				commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.inboundTag(), "reason", "busy", "transport", "udp")
				_, _ = l.udp.WriteToUDP(response, peer)
			}
		}
	}
}

func (l *DNSListener) queryLimit() int {
	queryBytes := l.currentPolicy().queryBytes
	if queryBytes >= 512 && queryBytes <= maxDNSMessageSize {
		return queryBytes
	}
	return defaultDNSMaxQueryBytes
}

func (l *DNSListener) acceptTCP() {
	defer l.wg.Done()
	degraded := false
	for {
		conn, err := l.tcp.Accept()
		if err != nil {
			if l.ctx.Err() != nil {
				return
			}
			errors.LogErrorInner(context.Background(), err, "DNS inbound TCP accept failed")
			if !isRetryableNetworkError(err) {
				l.health.setComponent(l.inboundTag(), "tcp", "failed", err, true)
				return
			}
			l.health.setComponent(l.inboundTag(), "tcp", "degraded", err, false)
			degraded = true
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
		policy := l.currentPolicy()
		peerIP, ok := clientIP(conn.RemoteAddr())
		if !ok || !clientAllowed(peerIP, policy.allowedClients) {
			commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.inboundTag(), "reason", "acl", "transport", "tcp")
			_ = conn.Close()
			continue
		}

		select {
		case policy.tcpSlots <- struct{}{}:
			if !l.trackConn(conn, true) {
				<-policy.tcpSlots
				_ = conn.Close()
				return
			}
			l.wg.Add(1)
			inboundTag := l.inboundTag()
			commonmetrics.Add("bypasscore_dns_tcp_connections_active", 1, "inbound", inboundTag)
			go l.serveTCP(conn, policy.tcpSlots, inboundTag)
		default:
			_ = conn.Close()
		}
	}
}

func (l *DNSListener) trackConn(conn net.Conn, add bool) bool {
	l.connMu.Lock()
	defer l.connMu.Unlock()
	if add {
		if l.conns == nil {
			return false
		}
		l.conns[conn] = struct{}{}
		return true
	}
	delete(l.conns, conn)
	return true
}

func (l *DNSListener) serveTCP(conn net.Conn, tcpSlots chan struct{}, inboundTag string) {
	defer l.wg.Done()
	defer func() { <-tcpSlots }()
	defer l.trackConn(conn, false)
	defer conn.Close()
	defer commonmetrics.Add("bypasscore_dns_tcp_connections_active", -1, "inbound", inboundTag)
	peerIP, ok := clientIP(conn.RemoteAddr())
	if !ok {
		return
	}

	var length [2]byte
	for {
		policy := l.currentPolicy()
		_ = conn.SetReadDeadline(time.Now().Add(dnsTCPIdleTimeout))
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			if !goerrors.Is(err, io.EOF) && l.ctx.Err() == nil {
				if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
					errors.LogErrorInner(context.Background(), err, "DNS inbound TCP frame failed")
				}
			}
			return
		}
		size := int(binary.BigEndian.Uint16(length[:]))
		if size == 0 || size > policy.queryBytes {
			return
		}
		request := make([]byte, size)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		now := time.Now()
		if !policy.rateLimiter.allow(peerIP, now) || !policy.globalLimiter.allow(now) {
			commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.inboundTag(), "reason", "rate", "transport", "tcp")
			response := errorResponse(request, dnsmessage.RCodeRefused)
			if len(response) == 0 || len(response) > maxDNSMessageSize {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(dnsTCPIdleTimeout))
			binary.BigEndian.PutUint16(length[:], uint16(len(response)))
			if writeAll(conn, length[:]) != nil || writeAll(conn, response) != nil {
				return
			}
			continue
		}
		commonmetrics.Inc("bypasscore_dns_queries_total", "inbound", l.inboundTag(), "transport", "tcp")

		select {
		case policy.querySlots <- struct{}{}:
			response, err := l.handleQuery(request, false)
			<-policy.querySlots
			if err != nil {
				errors.LogErrorInner(context.Background(), err, "DNS inbound TCP query failed")
				return
			}
			if len(response) == 0 || len(response) > maxDNSMessageSize {
				return
			}
			l.recordDNSResponse(response, "tcp")
			_ = conn.SetWriteDeadline(time.Now().Add(dnsTCPIdleTimeout))
			binary.BigEndian.PutUint16(length[:], uint16(len(response)))
			if err := writeAll(conn, length[:]); err != nil {
				return
			}
			if err := writeAll(conn, response); err != nil {
				return
			}
		case <-l.ctx.Done():
			return
		default:
			commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.inboundTag(), "reason", "busy", "transport", "tcp")
			response := errorResponse(request, dnsmessage.RCodeServerFailure)
			if len(response) == 0 || len(response) > maxDNSMessageSize {
				return
			}
			l.recordDNSResponse(response, "tcp")
			_ = conn.SetWriteDeadline(time.Now().Add(dnsTCPIdleTimeout))
			binary.BigEndian.PutUint16(length[:], uint16(len(response)))
			if writeAll(conn, length[:]) != nil || writeAll(conn, response) != nil {
				return
			}
		}
	}
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		payload = payload[n:]
	}
	return nil
}

func (l *DNSListener) handleQuery(raw []byte, udp bool) ([]byte, error) {
	return l.handleQueryContext(l.ctx, raw, udp)
}

func (l *DNSListener) handleQueryContext(ctx context.Context, raw []byte, udp bool) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	policy := l.currentPolicy()
	queryLimit := policy.queryBytes
	if queryLimit < 512 || queryLimit > maxDNSMessageSize {
		queryLimit = defaultDNSMaxQueryBytes
	}
	if len(raw) > queryLimit {
		return errorResponse(raw, dnsmessage.RCodeFormatError), nil
	}
	var request dnsmessage.Message
	if err := request.Unpack(raw); err != nil {
		return errorResponse(raw, dnsmessage.RCodeFormatError), nil
	}
	if request.Response {
		// A packet with QR=1 is not a query. Drop it quietly to avoid turning
		// spoofed responses into a log-amplification vector.
		return nil, nil
	}
	edns, err := inspectEDNS(&request)
	if err != nil {
		malformed := request
		malformed.Questions = nil
		return responseFor(&malformed, dnsmessage.RCodeFormatError, nil, udp, nil), nil
	}
	if edns != nil && edns.version != 0 {
		return responseFor(&request, rcodeBadVersion, nil, udp, edns), nil
	}
	if request.OpCode != 0 {
		return responseFor(&request, dnsmessage.RCodeNotImplemented, nil, udp, edns), nil
	}
	if request.RCode != dnsmessage.RCodeSuccess || len(request.Answers) != 0 || len(request.Authorities) != 0 {
		return responseFor(&request, dnsmessage.RCodeFormatError, nil, udp, edns), nil
	}
	if len(request.Questions) != 1 {
		malformed := request
		malformed.Questions = nil
		return responseFor(&malformed, dnsmessage.RCodeFormatError, nil, udp, edns), nil
	}

	question := request.Questions[0]
	if question.Class != dnsmessage.ClassINET {
		return responseFor(&request, dnsmessage.RCodeNotImplemented, nil, udp, edns), nil
	}
	action, ruleRCode := dnsActionForRules(policy.dnsRules, question)
	switch action {
	case dnsActionDrop:
		return nil, nil
	case dnsActionReturn:
		return responseFor(&request, ruleRCode, nil, udp, edns), nil
	case dnsActionDirect:
		return l.forwardRawQuery(ctx, &request, raw, udp, edns, policy.rawCache)
	case dnsActionHijack:
		if question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA {
			return responseFor(&request, dnsmessage.RCodeNotImplemented, nil, udp, edns), nil
		}
	}

	option := dnsfeature.IPOption{FakeEnable: true}
	switch question.Type {
	case dnsmessage.TypeA:
		option.IPv4Enable = true
	case dnsmessage.TypeAAAA:
		option.IPv6Enable = true
	}

	var ips []net.IP
	var ttl uint32
	var lookupErr error
	if client, ok := l.client.(dnsfeature.ContextClient); ok {
		ips, ttl, lookupErr = client.LookupIPContext(ctx, question.Name.String(), option)
	} else {
		ips, ttl, lookupErr = l.client.LookupIP(question.Name.String(), option)
	}
	rcode := dnsmessage.RCode(dnsfeature.RCodeFromError(lookupErr))
	if rcode > 0x0fff { // EDNS extended RCODEs are 12 bits in total.
		rcode = dnsmessage.RCodeServerFailure
	}
	if rcode > 15 && edns == nil {
		rcode = dnsmessage.RCodeServerFailure
	}
	if lookupErr != nil && rcode == dnsmessage.RCodeSuccess && !goerrors.Is(lookupErr, dnsfeature.ErrEmptyResponse) {
		rcode = dnsmessage.RCodeServerFailure
	}
	if rcode != dnsmessage.RCodeSuccess {
		ips = nil
	}

	answers := make([]dnsmessage.Resource, 0, len(ips))
	for _, ip := range ips {
		header := dnsmessage.ResourceHeader{
			Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: ttl,
		}
		switch question.Type {
		case dnsmessage.TypeA:
			v4 := ip.To4()
			if len(v4) != net.IPv4len {
				continue
			}
			var body dnsmessage.AResource
			copy(body.A[:], v4)
			answers = append(answers, dnsmessage.Resource{Header: header, Body: &body})
		case dnsmessage.TypeAAAA:
			if ip.To4() != nil {
				continue
			}
			v6 := ip.To16()
			if len(v6) != net.IPv6len {
				continue
			}
			var body dnsmessage.AAAAResource
			copy(body.AAAA[:], v6)
			answers = append(answers, dnsmessage.Resource{Header: header, Body: &body})
		}
	}
	return responseFor(&request, rcode, answers, udp, edns), nil
}

func (l *DNSListener) forwardRawQuery(ctx context.Context, request *dnsmessage.Message, raw []byte, udp bool, edns *ednsRequest, rawCache *dnsRawCache) ([]byte, error) {
	client, ok := l.client.(dnsfeature.RawContextClient)
	if !ok {
		return responseFor(request, dnsmessage.RCodeNotImplemented, nil, udp, edns), nil
	}
	now := time.Now()
	response, cached := rawCache.get(raw, now)
	if !cached {
		commonmetrics.Inc("bypasscore_dns_raw_cache_total", "inbound", l.inboundTag(), "result", "miss")
		var err error
		response, err = client.LookupRawContext(ctx, request.Questions[0].Name.String(), raw)
		if err != nil {
			return responseFor(request, dnsmessage.RCodeServerFailure, nil, udp, edns), nil
		}
		if err := dnsfeature.ValidateRawResponse(raw, response); err != nil {
			commonmetrics.Inc("bypasscore_dns_upstream_invalid_total", "inbound", l.inboundTag())
			errors.LogErrorInner(context.Background(), err, "DNS inbound rejected an invalid raw upstream response")
			return responseFor(request, dnsmessage.RCodeServerFailure, nil, udp, edns), nil
		}
		rawCache.put(raw, response, now)
	} else {
		commonmetrics.Inc("bypasscore_dns_raw_cache_total", "inbound", l.inboundTag(), "result", "hit")
	}
	if udp {
		limit := 512
		if edns != nil {
			limit = edns.payload
		}
		if len(response) > limit {
			return truncatedResponseFor(request, edns), nil
		}
	}
	return response, nil
}

func (l *DNSListener) recordDNSResponse(response []byte, transport string) {
	if len(response) < 4 {
		return
	}
	rcode := strconv.Itoa(int(response[3] & 0x0f))
	commonmetrics.Inc("bypasscore_dns_responses_total", "inbound", l.inboundTag(), "rcode", rcode, "transport", transport)
}

func truncatedResponseFor(request *dnsmessage.Message, edns *ednsRequest) []byte {
	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: request.ID, Response: true, OpCode: request.OpCode, Truncated: true,
			RecursionDesired: request.RecursionDesired, RecursionAvailable: true,
			CheckingDisabled: request.CheckingDisabled,
		},
		Questions: append([]dnsmessage.Question(nil), request.Questions...),
	}
	if edns != nil {
		var header dnsmessage.ResourceHeader
		if err := header.SetEDNS0(edns.payload, dnsmessage.RCodeSuccess, false); err != nil {
			return nil
		}
		response.Additionals = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.OPTResource{}}}
	}
	packed, err := response.AppendPack(nil)
	if err != nil {
		return nil
	}
	return packed
}

type ednsRequest struct {
	payload int
	version uint8
}

func inspectEDNS(request *dnsmessage.Message) (*ednsRequest, error) {
	var result *ednsRequest
	for _, extra := range request.Additionals {
		if extra.Header.Type != dnsmessage.TypeOPT || extra.Header.Name.String() != "." || result != nil {
			return nil, errors.New("invalid DNS additional section")
		}
		// A request cannot carry an extended response code, and EDNS Z bits
		// other than DO must be zero (RFC 6891 section 6.1.3).
		if extra.Header.TTL>>24 != 0 || extra.Header.TTL&0x00007fff != 0 {
			return nil, errors.New("invalid EDNS request flags")
		}
		payload := int(extra.Header.Class)
		if payload < 512 {
			payload = 512
		}
		if payload > maxDNSUDPPayload {
			payload = maxDNSUDPPayload
		}
		result = &ednsRequest{
			payload: payload, version: uint8(extra.Header.TTL >> 16),
		}
	}
	return result, nil
}

func responseFor(request *dnsmessage.Message, rcode dnsmessage.RCode, answers []dnsmessage.Resource, udp bool, edns *ednsRequest) []byte {
	if rcode > 15 && edns == nil {
		rcode = dnsmessage.RCodeServerFailure
	}
	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: request.ID, Response: true, OpCode: request.OpCode,
			RecursionDesired: request.RecursionDesired, RecursionAvailable: true,
			CheckingDisabled: request.CheckingDisabled, RCode: rcode & 0x0f,
		},
		Questions: append([]dnsmessage.Question(nil), request.Questions...),
		Answers:   answers,
	}
	if edns != nil {
		var header dnsmessage.ResourceHeader
		// The internal LookupIP interface does not preserve DNSSEC records, so
		// this listener must not advertise DNSSEC capability by echoing DO.
		if err := header.SetEDNS0(edns.payload, rcode, false); err != nil {
			return nil
		}
		response.Additionals = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.OPTResource{}}}
	}

	limit := maxDNSMessageSize
	if udp {
		limit = 512
		if edns != nil {
			limit = edns.payload
		}
	}
	packed, err := response.AppendPack(nil)
	if err != nil {
		return nil
	}
	if len(packed) <= limit {
		return packed
	}

	// A truncated response contains the question but no partial RR set, which
	// prompts a standards-compliant client to retry over TCP.
	response.Answers = nil
	response.Truncated = true
	packed, err = response.AppendPack(nil)
	if err != nil || len(packed) > limit {
		return nil
	}
	return packed
}

func errorResponse(raw []byte, rcode dnsmessage.RCode) []byte {
	if len(raw) < 2 {
		return nil
	}
	request := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(raw[:2])}}
	if len(raw) >= 4 {
		request.RecursionDesired = raw[2]&1 != 0
		request.CheckingDisabled = raw[3]&0x10 != 0
	}
	return responseFor(&request, rcode, nil, true, nil)
}
