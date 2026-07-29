// Package httpconnect implements an HTTPS forward-proxy outbound. It follows
// the upstream transport used by caddyserver/forwardproxy: establish TLS,
// negotiate HTTP/1.1 or HTTP/2 with ALPN, issue CONNECT with optional Basic
// proxy authentication, and expose the resulting tunnel as net.Conn.
package httpconnect

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	stderrors "errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
)

const defaultConnectTimeout = 10 * time.Second

// Handler dials destinations through an HTTPS CONNECT proxy.
type Handler struct {
	tag        string
	server     string
	username   string
	password   string
	serverName string
	caFile     string
	insecure   bool
	enableH2   bool
	timeout    time.Duration

	initOnce  sync.Once
	tlsConfig *tls.Config
	initErr   error
	closed    atomic.Bool

	cacheMu     sync.Mutex
	cachedH2    *http2.ClientConn
	cachedH2Raw net.Conn
	retiredH2   map[net.Conn]struct{}
}

// NewFromSettings creates an HTTPS CONNECT handler from an outbound's open
// settings map. Validation is performed by app/outbound before startup; any
// file or TLS initialization error is also retained and returned by Dial.
func NewFromSettings(tag, server string, settings map[string]any) *Handler {
	h := &Handler{
		tag:      tag,
		server:   server,
		enableH2: true,
		timeout:  defaultConnectTimeout,
	}
	h.username, _ = stringSetting(settings, "username")
	h.password, _ = stringSetting(settings, "password")
	h.serverName, _ = stringSetting(settings, "tlsServerName")
	h.caFile, _ = stringSetting(settings, "caFile")
	h.insecure, _ = boolSetting(settings, "insecureSkipVerify")
	if value, exists := boolSetting(settings, "enableHTTP2"); exists {
		h.enableH2 = value
	}
	if value, exists := integerSetting(settings, "connectTimeoutMs"); exists && value > 0 {
		h.timeout = time.Duration(value) * time.Millisecond
	}
	return h
}

func (h *Handler) Tag() string { return h.tag }

// Dial establishes a CONNECT tunnel. HTTPS forward proxies carry TCP only;
// UDP destinations fail closed instead of being sent outside the proxy.
func (h *Handler) Dial(ctx context.Context, dest bcnet.Destination) (net.Conn, error) {
	if dest.Network != bcnet.Network_TCP {
		return nil, errors.New("https proxy outbound supports TCP destinations only")
	}
	if dest.Address == nil || strings.TrimSpace(dest.Address.String()) == "" || dest.Port == 0 {
		return nil, errors.New("https proxy outbound requires a valid destination address and port")
	}
	if h.closed.Load() {
		return nil, errors.New("https proxy outbound is closed")
	}
	h.initOnce.Do(h.initialize)
	if h.initErr != nil {
		return nil, h.initErr
	}

	dialCtx, cancel := withTimeout(ctx, h.timeout)
	defer cancel()
	target := dest.NetAddr()
	if !httpguts.ValidHostHeader(target) {
		return nil, errors.New("https proxy outbound destination is not a valid CONNECT authority")
	}
	if h.enableH2 {
		if conn, attempted, err := h.dialCachedHTTP2(dialCtx, target); attempted {
			return conn, err
		}
	}

	raw, protocol, err := h.dialTLS(dialCtx)
	if err != nil {
		return nil, err
	}
	switch protocol {
	case "", "http/1.1":
		conn, err := h.connectHTTP1(dialCtx, raw, target)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		return conn, nil
	case "h2":
		client, err := (&http2.Transport{}).NewClientConn(raw)
		if err != nil {
			_ = raw.Close()
			return nil, errors.New("initialize HTTP/2 proxy connection").Base(err)
		}
		conn, err := h.connectHTTP2(dialCtx, raw, client, target, true)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		cached, accepted := h.cacheHTTP2(raw, client)
		if !accepted {
			_ = conn.Close()
			return nil, errors.New("https proxy outbound closed during CONNECT")
		}
		// A concurrently established healthy carrier may already have won the
		// cache slot. In that case this carrier remains private to its one
		// tunnel and is closed with the tunnel instead of being retained.
		if cached {
			conn.(*http2TunnelConn).closeRaw = false
		}
		return conn, nil
	default:
		_ = raw.Close()
		return nil, errors.New("HTTPS proxy negotiated unsupported ALPN protocol: ", protocol)
	}
}

func (h *Handler) initialize() {
	host, _, err := net.SplitHostPort(h.server)
	if err != nil {
		h.initErr = errors.New("invalid HTTPS proxy server address").Base(err)
		return
	}
	serverName := h.serverName
	if serverName == "" {
		serverName = strings.Trim(host, "[]")
	}
	var roots *x509.CertPool
	if h.caFile != "" {
		roots, err = x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		pem, readErr := os.ReadFile(h.caFile)
		if readErr != nil {
			h.initErr = errors.New("read HTTPS proxy caFile").Base(readErr)
			return
		}
		if !roots.AppendCertsFromPEM(pem) {
			h.initErr = errors.New("HTTPS proxy caFile contains no certificates")
			return
		}
	}
	nextProtos := []string{"http/1.1"}
	if h.enableH2 {
		nextProtos = []string{"h2", "http/1.1"}
	}
	h.tlsConfig = &tls.Config{
		ServerName:         serverName,
		RootCAs:            roots,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         nextProtos,
		InsecureSkipVerify: h.insecure, //nolint:gosec // explicit opt-in setting
	}
}

func (h *Handler) dialTLS(ctx context.Context) (net.Conn, string, error) {
	dialer := &net.Dialer{Timeout: h.timeout, KeepAlive: 30 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", h.server)
	if err != nil {
		return nil, "", errors.New("connect to HTTPS proxy ", h.server).Base(err)
	}
	tlsConn := tls.Client(raw, h.tlsConfig.Clone())
	handshakeCtx, cancel := withTimeout(ctx, h.timeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		_ = raw.Close()
		return nil, "", errors.New("HTTPS proxy TLS handshake failed").Base(err)
	}
	return tlsConn, tlsConn.ConnectionState().NegotiatedProtocol, nil
}

func (h *Handler) connectHTTP1(ctx context.Context, raw net.Conn, target string) (net.Conn, error) {
	deadline := time.Now().Add(h.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, err
	}
	request := h.connectRequest(ctx, target)
	request.Proto = "HTTP/1.1"
	request.ProtoMajor = 1
	request.ProtoMinor = 1
	if err := request.Write(raw); err != nil {
		return nil, errors.New("write HTTPS proxy CONNECT request").Base(err)
	}
	reader := bufio.NewReader(raw)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, errors.New("read HTTPS proxy CONNECT response").Base(err)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, &StatusError{StatusCode: response.StatusCode, Status: response.Status}
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &bufferedConn{Conn: raw, reader: reader}, nil
}

func (h *Handler) dialCachedHTTP2(ctx context.Context, target string) (net.Conn, bool, error) {
	h.cacheMu.Lock()
	client, raw := h.cachedH2, h.cachedH2Raw
	if client == nil || raw == nil {
		h.cacheMu.Unlock()
		return nil, false, nil
	}
	if !client.ReserveNewRequest() {
		state := client.State()
		h.cacheMu.Unlock()
		// A carrier at its concurrent-stream limit remains healthy. Open
		// another carrier for this request without evicting the cached one.
		if state.Closed || state.Closing {
			h.retireCachedHTTP2(client, raw)
		}
		return nil, false, nil
	}
	h.cacheMu.Unlock()
	conn, err := h.connectHTTP2(ctx, raw, client, target, false)
	if err == nil {
		return conn, true, nil
	}
	if ctx.Err() != nil {
		// Cancellation is scoped to this CONNECT stream. The shared carrier may
		// still be healthy and may already be carrying unrelated tunnels.
		return nil, true, err
	}
	var statusErr *StatusError
	if stderrors.As(err, &statusErr) {
		// Authentication/policy failures are stream responses, not carrier
		// failures. Preserve the reusable connection and report the response.
		return nil, true, err
	}

	// A carrier can die between CanTakeNewRequest and RoundTrip. Retire it and
	// let Dial establish one fresh connection instead of making every
	// subsequent request fail against the same stale cache entry.
	h.retireCachedHTTP2(client, raw)
	return nil, false, nil
}

func (h *Handler) connectHTTP2(ctx context.Context, raw net.Conn, client *http2.ClientConn, target string, closeRaw bool) (net.Conn, error) {
	streamCtx, cancelStream := context.WithCancel(context.Background())
	stopParentCancellation := context.AfterFunc(ctx, cancelStream)
	request := h.connectRequest(streamCtx, target)
	request.Proto = "HTTP/2.0"
	request.ProtoMajor = 2
	request.ProtoMinor = 0
	reader, writer := io.Pipe()
	request.Body = reader
	response, err := client.RoundTrip(request)
	if err != nil {
		stopParentCancellation()
		cancelStream()
		_ = writer.CloseWithError(err)
		_ = reader.CloseWithError(err)
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		}
		return nil, errors.New("HTTPS proxy HTTP/2 CONNECT failed").Base(err)
	}
	if response.StatusCode != http.StatusOK {
		stopParentCancellation()
		cancelStream()
		_ = writer.Close()
		_ = response.Body.Close()
		return nil, &StatusError{StatusCode: response.StatusCode, Status: response.Status}
	}
	if !stopParentCancellation() && ctx.Err() != nil {
		cancelStream()
		_ = writer.CloseWithError(ctx.Err())
		_ = response.Body.Close()
		return nil, ctx.Err()
	}
	return &http2TunnelConn{
		Conn:     raw,
		writer:   writer,
		reader:   response.Body,
		closeRaw: closeRaw,
		cancel:   cancelStream,
	}, nil
}

func (h *Handler) connectRequest(ctx context.Context, target string) *http.Request {
	request := (&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: target},
		Host:   target,
		Header: make(http.Header),
	}).WithContext(ctx)
	if h.username != "" || h.password != "" {
		credentials := base64.StdEncoding.EncodeToString([]byte(h.username + ":" + h.password))
		request.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}
	return request
}

// cacheHTTP2 returns whether raw became the shared cache entry and whether the
// handler is still open. A concurrently created carrier is kept private when a
// healthy cached carrier already exists, avoiding replacement churn and an
// unbounded retired-connection list under bursty first use.
func (h *Handler) cacheHTTP2(raw net.Conn, client *http2.ClientConn) (bool, bool) {
	h.cacheMu.Lock()
	if h.closed.Load() {
		h.cacheMu.Unlock()
		_ = raw.Close()
		return false, false
	}
	if h.cachedH2 != nil && h.cachedH2Raw != nil && h.cachedH2.CanTakeNewRequest() {
		h.cacheMu.Unlock()
		return false, true
	}
	oldClient, oldRaw := h.cachedH2, h.cachedH2Raw
	if oldRaw != nil {
		if h.retiredH2 == nil {
			h.retiredH2 = make(map[net.Conn]struct{})
		}
		h.retiredH2[oldRaw] = struct{}{}
	}
	h.cachedH2, h.cachedH2Raw = client, raw
	h.cacheMu.Unlock()
	if oldClient != nil {
		h.shutdownRetiredHTTP2(oldClient, oldRaw)
	}
	return true, true
}

func (h *Handler) retireCachedHTTP2(client *http2.ClientConn, raw net.Conn) {
	retired := false
	closeNow := false
	h.cacheMu.Lock()
	if h.cachedH2 == client && h.cachedH2Raw == raw {
		h.cachedH2, h.cachedH2Raw = nil, nil
		if h.closed.Load() {
			closeNow = true
		} else {
			if h.retiredH2 == nil {
				h.retiredH2 = make(map[net.Conn]struct{})
			}
			h.retiredH2[raw] = struct{}{}
			retired = true
		}
	}
	h.cacheMu.Unlock()
	if closeNow {
		_ = raw.Close()
		return
	}
	if retired {
		h.shutdownRetiredHTTP2(client, raw)
	}
}

// shutdownRetiredHTTP2 drains existing streams without accepting new ones,
// then removes the carrier from lifecycle tracking. Close can still force-close
// it while the graceful shutdown is waiting for long-lived tunnels.
func (h *Handler) shutdownRetiredHTTP2(client *http2.ClientConn, raw net.Conn) {
	go func() {
		if err := client.Shutdown(context.Background()); err != nil {
			_ = raw.Close()
		}
		h.cacheMu.Lock()
		delete(h.retiredH2, raw)
		h.cacheMu.Unlock()
	}()
}

// Close shuts down cached HTTP/2 carrier connections. Active HTTP/1.1
// tunnels and stream wrappers are owned and closed by the dispatcher.
func (h *Handler) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	h.cacheMu.Lock()
	conns := make([]net.Conn, 0, len(h.retiredH2)+1)
	for conn := range h.retiredH2 {
		conns = append(conns, conn)
	}
	if h.cachedH2Raw != nil {
		conns = append(conns, h.cachedH2Raw)
	}
	h.cachedH2, h.cachedH2Raw, h.retiredH2 = nil, nil, nil
	h.cacheMu.Unlock()
	var closeErrors []error
	for _, conn := range conns {
		if err := conn.Close(); err != nil && !stderrors.Is(err, net.ErrClosed) {
			closeErrors = append(closeErrors, err)
		}
	}
	return stderrors.Join(closeErrors...)
}

// StatusError reports a non-200 response from the upstream proxy.
type StatusError struct {
	StatusCode int
	Status     string
}

func (e *StatusError) Error() string {
	return "HTTPS proxy CONNECT failed: " + e.Status
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(value []byte) (int, error) { return c.reader.Read(value) }

func (c *bufferedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

type http2TunnelConn struct {
	net.Conn
	writer   *io.PipeWriter
	reader   io.ReadCloser
	closeRaw bool
	cancel   context.CancelFunc
	once     sync.Once
	closeErr error

	deadlineMu              sync.Mutex
	readTimer               *time.Timer
	writeTimer              *time.Timer
	readExpired             bool
	writeExpired            bool
	readDeadlineGeneration  uint64
	writeDeadlineGeneration uint64
}

func (c *http2TunnelConn) Read(value []byte) (int, error) {
	n, err := c.reader.Read(value)
	c.deadlineMu.Lock()
	expired := c.readExpired
	c.deadlineMu.Unlock()
	if err != nil && expired {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *http2TunnelConn) Write(value []byte) (int, error) {
	n, err := c.writer.Write(value)
	c.deadlineMu.Lock()
	expired := c.writeExpired
	c.deadlineMu.Unlock()
	if err != nil && expired {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *http2TunnelConn) Close() error {
	c.once.Do(func() {
		c.deadlineMu.Lock()
		c.readDeadlineGeneration++
		c.writeDeadlineGeneration++
		stopTimer(c.readTimer)
		stopTimer(c.writeTimer)
		c.deadlineMu.Unlock()
		if c.cancel != nil {
			c.cancel()
		}
		errs := []error{c.writer.Close(), c.reader.Close()}
		if c.closeRaw {
			errs = append(errs, c.Conn.Close())
		}
		c.closeErr = stderrors.Join(errs...)
	})
	return c.closeErr
}

func (c *http2TunnelConn) CloseWrite() error { return c.writer.Close() }
func (c *http2TunnelConn) CloseRead() error  { return c.reader.Close() }

func (c *http2TunnelConn) SetDeadline(deadline time.Time) error {
	if err := c.SetReadDeadline(deadline); err != nil {
		return err
	}
	return c.SetWriteDeadline(deadline)
}

func (c *http2TunnelConn) SetReadDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	stopTimer(c.readTimer)
	c.readTimer = nil
	c.readExpired = false
	c.readDeadlineGeneration++
	generation := c.readDeadlineGeneration
	if deadline.IsZero() {
		return nil
	}
	expire := func() {
		c.deadlineMu.Lock()
		if c.readDeadlineGeneration != generation {
			c.deadlineMu.Unlock()
			return
		}
		c.readExpired = true
		c.deadlineMu.Unlock()
		_ = c.reader.Close()
	}
	delay := time.Until(deadline)
	if delay <= 0 {
		go expire()
	} else {
		c.readTimer = time.AfterFunc(delay, expire)
	}
	return nil
}

func (c *http2TunnelConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	stopTimer(c.writeTimer)
	c.writeTimer = nil
	c.writeExpired = false
	c.writeDeadlineGeneration++
	generation := c.writeDeadlineGeneration
	if deadline.IsZero() {
		return nil
	}
	expire := func() {
		c.deadlineMu.Lock()
		if c.writeDeadlineGeneration != generation {
			c.deadlineMu.Unlock()
			return
		}
		c.writeExpired = true
		c.deadlineMu.Unlock()
		_ = c.writer.CloseWithError(os.ErrDeadlineExceeded)
	}
	delay := time.Until(deadline)
	if delay <= 0 {
		go expire()
	} else {
		c.writeTimer = time.AfterFunc(delay, expire)
	}
	return nil
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

func withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	// context.WithTimeout automatically keeps an earlier parent deadline while
	// still enforcing the configured upper bound when the parent deadline is
	// later. Merely detecting any parent deadline would incorrectly bypass the
	// outbound's connectTimeoutMs.
	return context.WithTimeout(ctx, timeout)
}

func stringSetting(settings map[string]any, key string) (string, bool) {
	if settings == nil {
		return "", false
	}
	value, exists := settings[key]
	if !exists {
		return "", false
	}
	result, ok := value.(string)
	return result, ok
}

func boolSetting(settings map[string]any, key string) (bool, bool) {
	if settings == nil {
		return false, false
	}
	value, exists := settings[key]
	if !exists {
		return false, false
	}
	result, ok := value.(bool)
	return result, ok
}

func integerSetting(settings map[string]any, key string) (int64, bool) {
	if settings == nil {
		return 0, false
	}
	switch value := settings[key].(type) {
	case int:
		return int64(value), true
	case int64:
		return value, true
	case float64:
		converted := int64(value)
		return converted, float64(converted) == value
	default:
		return 0, false
	}
}
