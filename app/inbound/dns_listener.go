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
	wg             sync.WaitGroup

	stateMu sync.Mutex
	state   dnsListenerState
	connMu  sync.Mutex
	conns   map[net.Conn]struct{}
}

// NewDNS creates a normal (non-transparent) DNS listener.
func NewDNS(cfg *Config, client dnsfeature.Client) *DNSListener {
	return &DNSListener{cfg: cfg, client: client, conns: make(map[net.Conn]struct{})}
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
	if err := l.startLocked(); err != nil {
		l.closeResourcesLocked()
		l.state = dnsListenerNew
		return err
	}
	l.state = dnsListenerRunning
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
	if l.client == nil {
		return errors.New("DNS inbound: DNS client is unavailable")
	}
	if l.cfg.Port < 1 || l.cfg.Port > 65535 {
		return errors.New("DNS inbound: port must be between 1 and 65535")
	}
	maxQueries, err := positiveLimit(l.cfg.MaxConcurrentQueries, defaultDNSMaxConcurrentQueries, "maxConcurrentQueries")
	if err != nil {
		return err
	}
	maxQueryBytes, err := queryByteLimit(l.cfg.MaxQueryBytes)
	if err != nil {
		return err
	}
	maxTCP, err := positiveLimit(l.cfg.MaxTCPConnections, defaultDNSMaxTCPConnections, "maxTCPConnections")
	if err != nil {
		return err
	}
	allowedClients, rateLimiter, globalLimiter, err := newDNSAccessPolicy(l.cfg)
	if err != nil {
		return err
	}
	dnsRules, err := compileDNSRules(l.cfg.DNSRules)
	if err != nil {
		return err
	}
	rawCache, err := newDNSRawCacheWithLimit(l.cfg.DNSRawCacheEntries, l.cfg.DNSRawCacheMaxTTLSeconds, l.cfg.DNSRawCacheMaxBytes)
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
	l.querySlots = make(chan struct{}, maxQueries)
	l.tcpSlots = make(chan struct{}, maxTCP)
	l.queryBytes = maxQueryBytes
	l.allowedClients = allowedClients
	l.rateLimiter = rateLimiter
	l.globalLimiter = globalLimiter
	l.dnsRules = dnsRules
	l.rawCache = rawCache
	l.connMu.Lock()
	l.conns = make(map[net.Conn]struct{})
	l.connMu.Unlock()
	listenHost := strings.TrimSpace(l.cfg.Listen)
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}
	if ip := net.ParseIP(strings.Trim(listenHost, "[]")); ip != nil && !ip.IsLoopback() && len(allowedClients) == 0 {
		errors.LogWarning(context.Background(), "DNS inbound[", l.cfg.Tag, "] is non-loopback without dnsAllowedClients")
	}
	addr := net.JoinHostPort(listenHost, strconv.Itoa(l.cfg.Port))
	if listenerType == "doh" {
		return l.startDoH(addr, maxTCP, maxQueries, serverTLS)
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
		errors.LogInfo(context.Background(), "inbound[", l.cfg.Tag, "] listening on ", scheme, addr)
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
		errors.LogInfo(context.Background(), "inbound[", l.cfg.Tag, "] listening on dns+udp://", addr)
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
		return nil
	}
	l.state = dnsListenerClosed
	l.closeResourcesLocked()
	return nil
}

func (l *DNSListener) closeResourcesLocked() {
	if l.cancel != nil {
		l.cancel()
	}
	if l.tcp != nil {
		_ = l.tcp.Close()
	}
	if l.udp != nil {
		_ = l.udp.Close()
	}
	if l.httpServer != nil {
		_ = l.httpServer.Close()
	}
	l.connMu.Lock()
	for conn := range l.conns {
		_ = conn.Close()
	}
	l.conns = nil
	l.connMu.Unlock()
	l.wg.Wait()
	l.tcp = nil
	l.udp = nil
	l.httpServer = nil
	l.ctx = nil
	l.cancel = nil
	l.querySlots = nil
	l.tcpSlots = nil
	l.allowedClients = nil
	l.rateLimiter = nil
	l.globalLimiter = nil
	l.dnsRules = nil
	l.rawCache = nil
}

func (l *DNSListener) serveUDP() {
	defer l.wg.Done()
	buf := make([]byte, l.queryLimit()+1)
	for {
		n, peer, err := l.udp.ReadFromUDP(buf)
		if err != nil {
			if l.ctx.Err() == nil {
				errors.LogErrorInner(context.Background(), err, "DNS inbound UDP read failed")
			}
			return
		}
		peerIP, ok := clientIP(peer)
		if !ok || !clientAllowed(peerIP, l.allowedClients) {
			commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.cfg.Tag, "reason", "acl", "transport", "udp")
			continue
		}
		now := time.Now()
		if !l.globalLimiter.allow(now) || !l.rateLimiter.allow(peerIP, now) {
			// Drop unauthorized/rate-limited UDP silently. Replying would let a
			// spoofed source turn the listener into a reflection endpoint.
			commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.cfg.Tag, "reason", "rate", "transport", "udp")
			continue
		}
		commonmetrics.Inc("bypasscore_dns_queries_total", "inbound", l.cfg.Tag, "transport", "udp")
		select {
		case l.querySlots <- struct{}{}:
			request := append([]byte(nil), buf[:n]...)
			l.wg.Add(1)
			go func() {
				defer l.wg.Done()
				defer func() { <-l.querySlots }()
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
				commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.cfg.Tag, "reason", "busy", "transport", "udp")
				_, _ = l.udp.WriteToUDP(response, peer)
			}
		}
	}
}

func (l *DNSListener) queryLimit() int {
	if l.queryBytes >= 512 && l.queryBytes <= maxDNSMessageSize {
		return l.queryBytes
	}
	return defaultDNSMaxQueryBytes
}

func (l *DNSListener) acceptTCP() {
	defer l.wg.Done()
	for {
		conn, err := l.tcp.Accept()
		if err != nil {
			if l.ctx.Err() != nil {
				return
			}
			errors.LogErrorInner(context.Background(), err, "DNS inbound TCP accept failed")
			select {
			case <-l.ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		peerIP, ok := clientIP(conn.RemoteAddr())
		if !ok || !clientAllowed(peerIP, l.allowedClients) {
			commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.cfg.Tag, "reason", "acl", "transport", "tcp")
			_ = conn.Close()
			continue
		}

		select {
		case l.tcpSlots <- struct{}{}:
			if !l.trackConn(conn, true) {
				<-l.tcpSlots
				_ = conn.Close()
				return
			}
			l.wg.Add(1)
			commonmetrics.Add("bypasscore_dns_tcp_connections_active", 1, "inbound", l.cfg.Tag)
			go l.serveTCP(conn)
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

func (l *DNSListener) serveTCP(conn net.Conn) {
	defer l.wg.Done()
	defer func() { <-l.tcpSlots }()
	defer l.trackConn(conn, false)
	defer conn.Close()
	defer commonmetrics.Add("bypasscore_dns_tcp_connections_active", -1, "inbound", l.cfg.Tag)
	peerIP, ok := clientIP(conn.RemoteAddr())
	if !ok {
		return
	}

	var length [2]byte
	for {
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
		if size == 0 || size > l.queryLimit() {
			return
		}
		request := make([]byte, size)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		now := time.Now()
		if !l.globalLimiter.allow(now) || !l.rateLimiter.allow(peerIP, now) {
			commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.cfg.Tag, "reason", "rate", "transport", "tcp")
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
		commonmetrics.Inc("bypasscore_dns_queries_total", "inbound", l.cfg.Tag, "transport", "tcp")

		select {
		case l.querySlots <- struct{}{}:
			response, err := l.handleQuery(request, false)
			<-l.querySlots
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
			commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.cfg.Tag, "reason", "busy", "transport", "tcp")
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
	if len(raw) > l.queryLimit() {
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
	action, ruleRCode := l.dnsAction(question)
	switch action {
	case dnsActionDrop:
		return nil, nil
	case dnsActionReturn:
		return responseFor(&request, ruleRCode, nil, udp, edns), nil
	case dnsActionDirect:
		return l.forwardRawQuery(ctx, &request, raw, udp, edns)
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

func (l *DNSListener) forwardRawQuery(ctx context.Context, request *dnsmessage.Message, raw []byte, udp bool, edns *ednsRequest) ([]byte, error) {
	client, ok := l.client.(dnsfeature.RawContextClient)
	if !ok {
		return responseFor(request, dnsmessage.RCodeNotImplemented, nil, udp, edns), nil
	}
	now := time.Now()
	response, cached := l.rawCache.get(raw, now)
	if !cached {
		commonmetrics.Inc("bypasscore_dns_raw_cache_total", "inbound", l.cfg.Tag, "result", "miss")
		var err error
		response, err = client.LookupRawContext(ctx, request.Questions[0].Name.String(), raw)
		if err != nil {
			return responseFor(request, dnsmessage.RCodeServerFailure, nil, udp, edns), nil
		}
		if err := dnsfeature.ValidateRawResponse(raw, response); err != nil {
			commonmetrics.Inc("bypasscore_dns_upstream_invalid_total", "inbound", l.cfg.Tag)
			errors.LogErrorInner(context.Background(), err, "DNS inbound rejected an invalid raw upstream response")
			return responseFor(request, dnsmessage.RCodeServerFailure, nil, udp, edns), nil
		}
		l.rawCache.put(raw, response, now)
	} else {
		commonmetrics.Inc("bypasscore_dns_raw_cache_total", "inbound", l.cfg.Tag, "result", "hit")
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
	commonmetrics.Inc("bypasscore_dns_responses_total", "inbound", l.cfg.Tag, "rcode", rcode, "transport", transport)
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
