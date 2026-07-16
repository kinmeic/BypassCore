package inbound

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	commonmetrics "github.com/eugene/bypasscore/common/metrics"
	"golang.org/x/net/http2"
)

func loadDNSServerTLSConfig(cfg *Config) (*tls.Config, error) {
	if strings.TrimSpace(cfg.DNSCertificateFile) == "" || strings.TrimSpace(cfg.DNSKeyFile) == "" {
		return nil, errors.New("DNS inbound: dot/doh require dnsCertificateFile and dnsKeyFile")
	}
	certificate, err := tls.LoadX509KeyPair(cfg.DNSCertificateFile, cfg.DNSKeyFile)
	if err != nil {
		return nil, errors.New("DNS inbound: failed to load TLS certificate").Base(err)
	}
	nextProtocols := []string{"h2", "http/1.1"}
	if strings.EqualFold(strings.TrimSpace(cfg.Type), "dot") {
		nextProtocols = []string{"dot"}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   nextProtocols,
	}, nil
}

type dohConnLease struct {
	slots chan struct{}
	tag   string
}

func (l *DNSListener) startDoH(address string, tlsConfig *tls.Config) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.New("DNS inbound DoH listen failed: ", address).Base(err)
	}
	l.tcp = tls.NewListener(listener, tlsConfig)
	path := strings.TrimSpace(l.cfg.DNSDoHPath)
	if path == "" {
		path = "/dns-query"
	}
	if !strings.HasPrefix(path, "/") {
		_ = l.tcp.Close()
		return errors.New("DNS inbound: dnsDoHPath must start with /")
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, l.handleDoH)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		TLSConfig:         tlsConfig,
		ConnState:         l.handleDoHConnState,
	}
	if err := http2.ConfigureServer(server, &http2.Server{MaxConcurrentStreams: uint32(maxDoHConcurrentStreams)}); err != nil {
		_ = l.tcp.Close()
		return errors.New("DNS inbound: configure HTTP/2").Base(err)
	}
	l.httpServer = server
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		if err := server.Serve(l.tcp); err != nil && err != http.ErrServerClosed && l.ctx.Err() == nil {
			errors.LogErrorInner(context.Background(), err, "DNS inbound DoH serve failed")
		}
	}()
	errors.LogInfo(context.Background(), "inbound[", l.inboundTag(), "] listening on doh://", address, path)
	return nil
}

func (l *DNSListener) handleDoHConnState(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		policy := l.currentPolicy()
		select {
		case policy.tcpSlots <- struct{}{}:
			lease := dohConnLease{slots: policy.tcpSlots, tag: l.inboundTag()}
			l.connMu.Lock()
			if l.dohConns == nil {
				l.connMu.Unlock()
				<-policy.tcpSlots
				_ = conn.Close()
				return
			}
			l.dohConns[conn] = lease
			l.connMu.Unlock()
			commonmetrics.Add("bypasscore_dns_tcp_connections_active", 1, "inbound", lease.tag)
		default:
			_ = conn.Close()
		}
	case http.StateClosed, http.StateHijacked:
		l.connMu.Lock()
		lease, exists := l.dohConns[conn]
		if exists {
			delete(l.dohConns, conn)
		}
		l.connMu.Unlock()
		if exists {
			<-lease.slots
			commonmetrics.Add("bypasscore_dns_tcp_connections_active", -1, "inbound", lease.tag)
		}
	}
}

func (l *DNSListener) handleDoH(writer http.ResponseWriter, request *http.Request) {
	policy := l.currentPolicy()
	ip, ok := remoteRequestIP(request.RemoteAddr)
	if !ok || !clientAllowed(ip, policy.allowedClients) {
		commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.inboundTag(), "reason", "acl", "transport", "doh")
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}
	now := time.Now()
	if !policy.globalLimiter.allow(now) || !policy.rateLimiter.allow(ip, now) {
		commonmetrics.Inc("bypasscore_dns_rejected_total", "inbound", l.inboundTag(), "reason", "rate", "transport", "doh")
		http.Error(writer, "rate limited", http.StatusTooManyRequests)
		return
	}
	var query []byte
	var err error
	switch request.Method {
	case http.MethodPost:
		if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0])); mediaType != "application/dns-message" {
			http.Error(writer, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		query, err = io.ReadAll(io.LimitReader(request.Body, int64(policy.queryBytes+1)))
	case http.MethodGet:
		query, err = base64.RawURLEncoding.DecodeString(request.URL.Query().Get("dns"))
	default:
		writer.Header().Set("Allow", "GET, POST")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil || len(query) == 0 || len(query) > policy.queryBytes {
		http.Error(writer, "invalid DNS query", http.StatusBadRequest)
		return
	}
	commonmetrics.Inc("bypasscore_dns_queries_total", "inbound", l.inboundTag(), "transport", "doh")
	select {
	case policy.querySlots <- struct{}{}:
		defer func() { <-policy.querySlots }()
	case <-l.ctx.Done():
		http.Error(writer, "shutting down", http.StatusServiceUnavailable)
		return
	default:
		http.Error(writer, "busy", http.StatusServiceUnavailable)
		return
	}
	response, err := l.handleQueryContext(request.Context(), query, false)
	if err != nil {
		http.Error(writer, "DNS processing failed", http.StatusInternalServerError)
		return
	}
	if len(response) == 0 {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	l.recordDNSResponse(response, "doh")
	writer.Header().Set("Content-Type", "application/dns-message")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(response)
}

func remoteRequestIP(remote string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}
