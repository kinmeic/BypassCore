// Package control exposes the local BypassCore control plane over HTTP/JSON
// carried by a Unix domain socket. It deliberately has no TCP listener.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultSocket           = "/run/bypasscore/control.sock"
	defaultMaxRequestBytes  = int64(512 << 10)
	defaultMaxInflightBytes = int64(2 << 20)
)

type Config struct {
	Enabled                 bool   `json:"enabled,omitempty"`
	Socket                  string `json:"socket,omitempty"`
	Mode                    string `json:"mode,omitempty"`
	MaxRequestBytes         int64  `json:"maxRequestBytes,omitempty"`
	MaxInflightRequestBytes int64  `json:"maxInflightRequestBytes,omitempty"`
	MaxConcurrentRequests   int    `json:"maxConcurrentRequests,omitempty"`
}

type Capabilities struct {
	Version      string   `json:"version"`
	ConfigSchema int      `json:"configSchema"`
	Features     []string `json:"features"`
}

type RouteExplainRequest struct {
	Destination string `json:"destination"`
	InboundTag  string `json:"inboundTag,omitempty"`
	Source      string `json:"source,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
}

type DNSResolveRequest struct {
	Domain string `json:"domain"`
	IPv4   *bool  `json:"ipv4,omitempty"`
	IPv6   *bool  `json:"ipv6,omitempty"`
}

type TCPProbeRequest struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	TimeoutMs   int    `json:"timeoutMs,omitempty"`
	OutboundTag string `json:"outboundTag,omitempty"`
}

type HandshakeProbeRequest struct {
	TimeoutMs   int    `json:"timeoutMs,omitempty"`
	OutboundTag string `json:"outboundTag"`
}

type URLTestRequest struct {
	URL         string `json:"url"`
	TimeoutMs   int    `json:"timeoutMs,omitempty"`
	OutboundTag string `json:"outboundTag"`
}

type Backend interface {
	Status(context.Context) (any, error)
	Ready(context.Context) (any, error)
	Validate(context.Context, []byte) (any, error)
	Reload(context.Context, []byte, ...string) (any, error)
	Explain(context.Context, RouteExplainRequest) (any, error)
	Resolve(context.Context, DNSResolveRequest) (any, error)
	Observatory(context.Context) (any, error)
	Metrics(context.Context) (any, error)
	DNSResults(context.Context) (any, error)
	DNSNFTSets(context.Context) (any, error)
	ProbeDNSNFTSets(context.Context) (any, error)
	TCPProbe(context.Context, TCPProbeRequest) (any, error)
	HandshakeProbe(context.Context, HandshakeProbeRequest) (any, error)
	URLTest(context.Context, URLTestRequest) (any, error)
}

// APIError is returned as a stable machine-readable control-plane error.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *APIError) Error() string { return e.Message }

type Server struct {
	config        Config
	backend       Backend
	capabilities  Capabilities
	listener      net.Listener
	httpServer    *http.Server
	semaphore     chan struct{}
	mutation      chan struct{}
	inflightBytes atomic.Int64
	mu            sync.Mutex
	closed        bool
	socketInfo    os.FileInfo
}

func New(config *Config, backend Backend, capabilities Capabilities) (*Server, error) {
	if backend == nil {
		return nil, errors.New("control: nil backend")
	}
	c, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	return &Server{config: c, backend: backend, capabilities: capabilities, semaphore: make(chan struct{}, c.MaxConcurrentRequests), mutation: make(chan struct{}, 1)}, nil
}

// Validate checks control transport settings without opening the socket.
func Validate(config *Config) error { _, err := normalizeConfig(config); return err }

// EquivalentConfig compares effective control settings, including defaults.
func EquivalentConfig(left, right *Config) bool {
	leftEnabled := left != nil && left.Enabled
	rightEnabled := right != nil && right.Enabled
	if leftEnabled != rightEnabled {
		return false
	}
	if !leftEnabled {
		return true
	}
	l, leftErr := normalizeConfig(left)
	r, rightErr := normalizeConfig(right)
	return leftErr == nil && rightErr == nil && l == r
}

func normalizeConfig(config *Config) (Config, error) {
	if config == nil || !config.Enabled {
		return Config{}, errors.New("control: server is disabled")
	}
	c := *config
	if strings.TrimSpace(c.Socket) == "" {
		c.Socket = DefaultSocket
	}
	if !filepath.IsAbs(c.Socket) {
		return Config{}, errors.New("control: socket path must be absolute")
	}
	if c.MaxRequestBytes < 0 {
		return Config{}, errors.New("control: maxRequestBytes must not be negative")
	}
	if c.MaxRequestBytes == 0 {
		c.MaxRequestBytes = defaultMaxRequestBytes
	}
	if c.MaxRequestBytes > 2<<20 {
		return Config{}, errors.New("control: maxRequestBytes exceeds 2 MiB")
	}
	if c.MaxInflightRequestBytes < 0 {
		return Config{}, errors.New("control: maxInflightRequestBytes must not be negative")
	}
	if c.MaxInflightRequestBytes == 0 {
		c.MaxInflightRequestBytes = defaultMaxInflightBytes
	}
	if c.MaxInflightRequestBytes < c.MaxRequestBytes || c.MaxInflightRequestBytes > 8<<20 {
		return Config{}, errors.New("control: maxInflightRequestBytes must be between maxRequestBytes and 8 MiB")
	}
	if c.MaxConcurrentRequests < 0 {
		return Config{}, errors.New("control: maxConcurrentRequests must not be negative")
	}
	if c.MaxConcurrentRequests == 0 {
		c.MaxConcurrentRequests = 16
	}
	if c.MaxConcurrentRequests > 64 {
		return Config{}, errors.New("control: maxConcurrentRequests exceeds 64")
	}
	mode, err := parseMode(c.Mode)
	if err != nil {
		return Config{}, err
	}
	c.Mode = fmt.Sprintf("%04o", mode.Perm())
	return c, nil
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("control: server is closed")
	}
	if s.listener != nil {
		return errors.New("control: server already started")
	}
	parent := filepath.Dir(s.config.Socket)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("control: create socket directory: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("control: socket parent must be a real directory")
	}
	if info, err := os.Lstat(s.config.Socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("control: refusing to replace non-socket path")
		}
		if conn, dialErr := net.DialTimeout("unix", s.config.Socket, 100*time.Millisecond); dialErr == nil {
			_ = conn.Close()
			return errors.New("control: socket is already in use")
		}
		current, currentErr := os.Lstat(s.config.Socket)
		if currentErr != nil || !os.SameFile(info, current) {
			return errors.New("control: socket path changed during stale check")
		}
		if err := os.Remove(s.config.Socket); err != nil {
			return fmt.Errorf("control: remove stale socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("control: inspect socket path: %w", err)
	}
	listener, err := net.Listen("unix", s.config.Socket)
	if err != nil {
		return fmt.Errorf("control: listen: %w", err)
	}
	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(false)
	}
	mode, _ := parseMode(s.config.Mode)
	if err := os.Chmod(s.config.Socket, mode); err != nil {
		_ = listener.Close()
		_ = os.Remove(s.config.Socket)
		return fmt.Errorf("control: chmod socket: %w", err)
	}
	s.socketInfo, err = os.Lstat(s.config.Socket)
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(s.config.Socket)
		return fmt.Errorf("control: inspect created socket: %w", err)
	}
	s.listener = listener
	s.httpServer = &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		if err := s.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			// The daemon status endpoint reports listener failures; there is no
			// logger dependency here so this leaf package stays reusable.
		}
	}()
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	server := s.httpServer
	listener := s.listener
	s.mu.Unlock()
	var closeErr error
	if server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr = server.Shutdown(ctx)
		cancel()
		if closeErr != nil {
			_ = server.Close()
		}
	} else if listener != nil {
		closeErr = listener.Close()
	}
	if info, err := os.Lstat(s.config.Socket); err == nil && info.Mode()&os.ModeSocket != 0 && s.socketInfo != nil && os.SameFile(info, s.socketInfo) {
		if err := os.Remove(s.config.Socket); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.capabilities) })
	mux.HandleFunc("GET /v1/status", s.noBody(s.backend.Status))
	mux.HandleFunc("GET /v1/ready", s.noBody(s.backend.Ready))
	mux.HandleFunc("GET /v1/observatory", s.noBody(s.backend.Observatory))
	mux.HandleFunc("GET /v1/metrics", s.noBody(s.backend.Metrics))
	mux.HandleFunc("GET /v1/dns/results", s.noBody(s.backend.DNSResults))
	mux.HandleFunc("GET /v1/dns/nftsets", s.noBody(s.backend.DNSNFTSets))
	mux.HandleFunc("POST /v1/dns/nftsets/probe", s.mutationOnly(s.noBody(s.backend.ProbeDNSNFTSets)))
	mux.HandleFunc("POST /v1/config/validate", s.mutationOnly(s.rawBody(s.backend.Validate)))
	mux.HandleFunc("POST /v1/config/reload", s.mutationOnly(s.reloadBody()))
	mux.HandleFunc("POST /v1/route/explain", decodeBody(s, func(ctx context.Context, request RouteExplainRequest) (any, error) {
		return s.backend.Explain(ctx, request)
	}))
	mux.HandleFunc("POST /v1/dns/resolve", decodeBody(s, func(ctx context.Context, request DNSResolveRequest) (any, error) {
		return s.backend.Resolve(ctx, request)
	}))
	mux.HandleFunc("POST /v1/network/tcp-probe", decodeBody(s, func(ctx context.Context, request TCPProbeRequest) (any, error) {
		return s.backend.TCPProbe(ctx, request)
	}))
	mux.HandleFunc("POST /v1/network/handshake-probe", decodeBody(s, func(ctx context.Context, request HandshakeProbeRequest) (any, error) {
		return s.backend.HandshakeProbe(ctx, request)
	}))
	mux.HandleFunc("POST /v1/network/url-test", decodeBody(s, func(ctx context.Context, request URLTestRequest) (any, error) {
		return s.backend.URLTest(ctx, request)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.semaphore <- struct{}{}:
			defer func() { <-s.semaphore }()
		default:
			writeError(w, &APIError{Code: "busy", Message: "too many concurrent control requests", Status: http.StatusServiceUnavailable})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) noBody(call func(context.Context) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := call(r.Context())
		writeResult(w, result, err)
	}
}

func (s *Server) rawBody(call func(context.Context, []byte) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, release, err := s.readBody(w, r)
		if err != nil {
			writeError(w, err)
			return
		}
		defer release()
		result, err := call(r.Context(), body)
		writeResult(w, result, err)
	}
}

func (s *Server) reloadBody() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, release, err := s.readBody(w, r)
		if err != nil {
			writeError(w, err)
			return
		}
		defer release()
		result, err := s.backend.Reload(r.Context(), body, r.Header.Get("If-Match"))
		writeResult(w, result, err)
	}
}

func (s *Server) mutationOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.mutation <- struct{}{}:
			defer func() { <-s.mutation }()
		default:
			writeError(w, &APIError{Code: "busy", Message: "a validate or reload request is already running", Status: http.StatusServiceUnavailable})
			return
		}
		next(w, r)
	}
}

func (s *Server) readBody(w http.ResponseWriter, r *http.Request) ([]byte, func(), error) {
	reserved := s.config.MaxRequestBytes
	for {
		current := s.inflightBytes.Load()
		if current+reserved > s.config.MaxInflightRequestBytes {
			return nil, nil, &APIError{Code: "busy", Message: "control request byte budget exhausted", Status: http.StatusServiceUnavailable}
		}
		if s.inflightBytes.CompareAndSwap(current, current+reserved) {
			break
		}
	}
	release := func() { s.inflightBytes.Add(-reserved) }
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.config.MaxRequestBytes))
	if err != nil {
		release()
		return nil, nil, &APIError{Code: "request_too_large", Message: err.Error(), Status: http.StatusRequestEntityTooLarge}
	}
	return body, release, nil
}

func decodeBody[T any](s *Server, call func(context.Context, T) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, release, err := s.readBodyBudget(); err != nil {
			writeError(w, err)
			return
		} else {
			defer release()
		}
		var request T
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.config.MaxRequestBytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeError(w, &APIError{Code: "invalid_request", Message: err.Error(), Status: http.StatusBadRequest})
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			writeError(w, &APIError{Code: "invalid_request", Message: "request must contain one JSON value", Status: http.StatusBadRequest})
			return
		}
		result, err := call(r.Context(), request)
		writeResult(w, result, err)
	}
}

func (s *Server) readBodyBudget() (int64, func(), error) {
	reserved := s.config.MaxRequestBytes
	for {
		current := s.inflightBytes.Load()
		if current+reserved > s.config.MaxInflightRequestBytes {
			return 0, nil, &APIError{Code: "busy", Message: "control request byte budget exhausted", Status: http.StatusServiceUnavailable}
		}
		if s.inflightBytes.CompareAndSwap(current, current+reserved) {
			return reserved, func() { s.inflightBytes.Add(-reserved) }, nil
		}
	}
}

func writeResult(w http.ResponseWriter, result any, err error) {
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func writeError(w http.ResponseWriter, err error) {
	api := new(APIError)
	if !errors.As(err, &api) {
		api = &APIError{Code: "internal_error", Message: err.Error(), Status: http.StatusInternalServerError}
	}
	if api.Status == 0 {
		api.Status = http.StatusBadRequest
	}
	writeJSON(w, api.Status, map[string]any{"error": api})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		status = http.StatusInternalServerError
		payload = []byte(`{"error":{"code":"encode_error","message":"response encoding failed"}}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(payload, '\n'))
}

func parseMode(raw string) (os.FileMode, error) {
	if strings.TrimSpace(raw) == "" {
		return 0o660, nil
	}
	value, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(raw), "0o"), 8, 32)
	if err != nil || value > 0o777 {
		return 0, errors.New("control: mode must be an octal permission such as 0660")
	}
	return os.FileMode(value), nil
}
