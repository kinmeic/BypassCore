package metrics

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	commonmetrics "github.com/eugene/bypasscore/common/metrics"
)

type Config struct {
	Listen         string   `json:"listen,omitempty"`
	AllowedClients []string `json:"allowedClients,omitempty"`
	EnablePprof    bool     `json:"enablePprof,omitempty"`
}

type Server struct {
	config  *Config
	allowed []netip.Prefix
	server  *http.Server
	listen  net.Listener
	healthy atomic.Bool
	mu      sync.Mutex
	closed  bool
}

func New(config *Config) (*Server, error) {
	if config == nil {
		return nil, errors.New("metrics: nil configuration")
	}
	allowed := make([]netip.Prefix, 0, len(config.AllowedClients))
	for _, raw := range config.AllowedClients {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, errors.New("metrics: invalid allowedClients prefix ", raw).Base(err)
		}
		allowed = append(allowed, prefix.Masked())
	}
	return &Server{config: config, allowed: allowed}, nil
}

// Validate checks the listener exposure policy without binding a port.
func (s *Server) Validate() error {
	address := strings.TrimSpace(s.config.Listen)
	if address == "" {
		address = "127.0.0.1:9090"
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("metrics: listen must be host:port").Base(err)
	}
	host = strings.Trim(host, "[]")
	isLoopback := strings.EqualFold(host, "localhost")
	if ip := net.ParseIP(host); ip != nil {
		isLoopback = ip.IsLoopback()
	} else if !isLoopback {
		return errors.New("metrics: listen host must be a literal IP or localhost")
	}
	if !isLoopback && len(s.allowed) == 0 {
		return errors.New("metrics: non-loopback listen requires allowedClients")
	}
	return nil
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("metrics: server is closed")
	}
	if s.server != nil {
		return errors.New("metrics: server is already started")
	}
	if err := s.Validate(); err != nil {
		return err
	}
	address := strings.TrimSpace(s.config.Listen)
	if address == "" {
		address = "127.0.0.1:9090"
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	s.listen = listener
	server := &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	s.server = server
	s.healthy.Store(true)
	go func() {
		defer s.healthy.Store(false)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errors.LogErrorInner(context.Background(), err, "metrics server failed")
		}
	}()
	errors.LogInfo(context.Background(), "metrics listening on http://", listener.Addr().String())
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	server := s.server
	s.mu.Unlock()
	s.healthy.Store(false)
	if server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		status := http.StatusServiceUnavailable
		if s.healthy.Load() {
			status = http.StatusOK
		}
		writer.WriteHeader(status)
		_ = json.NewEncoder(writer).Encode(map[string]any{"ok": status == http.StatusOK})
	})
	mux.HandleFunc("/metrics", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = commonmetrics.WritePrometheus(writer)
	})
	if s.config.EnablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !s.clientAllowed(request.RemoteAddr) {
			http.Error(writer, "forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(writer, request)
	})
}

func (s *Server) clientAllowed(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if len(s.allowed) == 0 {
		return ip.IsLoopback()
	}
	for _, prefix := range s.allowed {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
