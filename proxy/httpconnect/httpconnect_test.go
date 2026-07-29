package httpconnect

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	stderrors "errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	bcnet "github.com/eugene/bypasscore/common/net"
)

type testHTTPSProxy struct {
	server       *httptest.Server
	caFile       string
	targets      chan string
	protocols    chan int
	connections  atomic.Int32
	responseLag  atomic.Int64
	rejectTarget atomic.Pointer[string]
}

func newTestHTTPSProxy(t *testing.T, enableHTTP2 bool, username, password string) *testHTTPSProxy {
	t.Helper()
	proxy := &testHTTPSProxy{
		targets:   make(chan string, 64),
		protocols: make(chan int, 64),
	}
	expectedAuth := ""
	if username != "" || password != "" {
		expectedAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		if request.Header.Get("Proxy-Authorization") != expectedAuth {
			w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
			http.Error(w, "authentication required", http.StatusProxyAuthRequired)
			return
		}
		if rejected := proxy.rejectTarget.Load(); rejected != nil && request.Host == *rejected {
			http.Error(w, "target forbidden", http.StatusForbidden)
			return
		}
		if delay := time.Duration(proxy.responseLag.Load()); delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-request.Context().Done():
				return
			}
		}
		proxy.targets <- request.Host
		proxy.protocols <- request.ProtoMajor
		if request.ProtoMajor == 1 {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijacking unavailable", http.StatusInternalServerError)
				return
			}
			conn, buffered, err := hijacker.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			if err := buffered.Flush(); err != nil {
				return
			}
			_, _ = io.Copy(conn, conn)
			return
		}

		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		flusher.Flush()
		buffer := make([]byte, 1024)
		for {
			n, err := request.Body.Read(buffer)
			if n > 0 {
				if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
					return
				}
				flusher.Flush()
			}
			if err != nil {
				return
			}
		}
	})
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = enableHTTP2
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			proxy.connections.Add(1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	proxy.server = server

	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	proxy.caFile = filepath.Join(t.TempDir(), "proxy-ca.pem")
	if err := os.WriteFile(proxy.caFile, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	return proxy
}

func (p *testHTTPSProxy) address() string {
	return p.server.Listener.Addr().String()
}

func testTunnel(t *testing.T, handler *Handler, target string) {
	t.Helper()
	conn, err := handler.Dial(context.Background(), bcnet.TCPDestination(bcnet.DomainAddress(target), 443))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "ping" {
		t.Fatalf("tunnel response = %q, want ping", response)
	}
}

func TestHTTPSConnectHTTP1(t *testing.T) {
	proxy := newTestHTTPSProxy(t, false, "user", "pass")
	handler := NewFromSettings("https-out", proxy.address(), map[string]any{
		"username":    "user",
		"password":    "pass",
		"caFile":      proxy.caFile,
		"enableHTTP2": false,
	})
	defer handler.Close()
	testTunnel(t, handler, "route.example")
	if target := <-proxy.targets; target != "route.example:443" {
		t.Fatalf("CONNECT target = %q", target)
	}
	if protocol := <-proxy.protocols; protocol != 1 {
		t.Fatalf("proxy protocol = HTTP/%d, want HTTP/1.1", protocol)
	}
}

func TestHTTPSConnectIPv6Authority(t *testing.T) {
	proxy := newTestHTTPSProxy(t, false, "", "")
	handler := NewFromSettings("https-out", proxy.address(), map[string]any{
		"caFile":      proxy.caFile,
		"enableHTTP2": false,
	})
	defer handler.Close()

	conn, err := handler.Dial(context.Background(), bcnet.TCPDestination(
		bcnet.IPAddress(net.ParseIP("2001:db8::1")), 443))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if target := <-proxy.targets; target != "[2001:db8::1]:443" {
		t.Fatalf("IPv6 CONNECT target = %q", target)
	}
}

func TestHTTPSConnectHTTP2ReusesCarrier(t *testing.T) {
	proxy := newTestHTTPSProxy(t, true, "user", "pass")
	handler := NewFromSettings("https-out", proxy.address(), map[string]any{
		"username": "user",
		"password": "pass",
		"caFile":   proxy.caFile,
	})
	defer handler.Close()

	testTunnel(t, handler, "one.example")
	testTunnel(t, handler, "two.example")
	for _, expected := range []string{"one.example:443", "two.example:443"} {
		if target := <-proxy.targets; target != expected {
			t.Fatalf("CONNECT target = %q, want %q", target, expected)
		}
		if protocol := <-proxy.protocols; protocol != 2 {
			t.Fatalf("proxy protocol = HTTP/%d, want HTTP/2", protocol)
		}
	}
	if connections := proxy.connections.Load(); connections != 1 {
		t.Fatalf("HTTPS proxy TLS connections = %d, want one reused HTTP/2 carrier", connections)
	}
}

func TestHTTPSConnectHTTP2TunnelOutlivesDialContext(t *testing.T) {
	proxy := newTestHTTPSProxy(t, true, "", "")
	handler := NewFromSettings("https-out", proxy.address(), map[string]any{"caFile": proxy.caFile})
	defer handler.Close()

	ctx, cancel := context.WithCancel(context.Background())
	conn, err := handler.Dial(ctx, bcnet.TCPDestination(bcnet.DomainAddress("route.example"), 443))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("still-open")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("still-open"))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "still-open" {
		t.Fatalf("response after dial-context cancellation = %q", response)
	}
}

func TestHTTPSConnectTimeoutOverridesLaterParentDeadline(t *testing.T) {
	proxy := newTestHTTPSProxy(t, true, "", "")
	proxy.responseLag.Store(int64(300 * time.Millisecond))
	handler := NewFromSettings("https-out", proxy.address(), map[string]any{
		"caFile":           proxy.caFile,
		"connectTimeoutMs": 50,
	})
	defer handler.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	_, err := handler.Dial(ctx, bcnet.TCPDestination(bcnet.DomainAddress("slow.example"), 443))
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("slow CONNECT unexpectedly succeeded")
	}
	if !stderrors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("slow CONNECT error = %v, want context deadline exceeded", err)
	}
	if elapsed >= 200*time.Millisecond {
		t.Fatalf("connectTimeoutMs was bypassed by later parent deadline: elapsed=%v", elapsed)
	}
}

func TestHTTPSConnectHTTP2RecoversFromStaleCachedCarrier(t *testing.T) {
	proxy := newTestHTTPSProxy(t, true, "", "")
	handler := NewFromSettings("https-out", proxy.address(), map[string]any{"caFile": proxy.caFile})
	defer handler.Close()

	testTunnel(t, handler, "one.example")
	handler.cacheMu.Lock()
	raw := handler.cachedH2Raw
	if raw == nil {
		handler.cacheMu.Unlock()
		t.Fatal("first HTTP/2 carrier was not cached")
	}
	_ = raw.Close()
	handler.cacheMu.Unlock()

	testTunnel(t, handler, "two.example")
	if connections := proxy.connections.Load(); connections < 2 {
		t.Fatalf("HTTPS proxy TLS connections = %d, want a replacement carrier", connections)
	}
	deadline := time.Now().Add(time.Second)
	for {
		handler.cacheMu.Lock()
		retired := len(handler.retiredH2)
		handler.cacheMu.Unlock()
		if retired == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stale HTTP/2 carriers retained after shutdown: %d", retired)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestHTTPSConnectCanceledStreamKeepsSharedCarrier(t *testing.T) {
	proxy := newTestHTTPSProxy(t, true, "", "")
	handler := NewFromSettings("https-out", proxy.address(), map[string]any{"caFile": proxy.caFile})
	defer handler.Close()

	testTunnel(t, handler, "warm.example")
	proxy.responseLag.Store(int64(300 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	_, err := handler.Dial(ctx, bcnet.TCPDestination(bcnet.DomainAddress("slow.example"), 443))
	cancel()
	if err == nil {
		t.Fatal("canceled HTTP/2 CONNECT unexpectedly succeeded")
	}
	proxy.responseLag.Store(0)
	testTunnel(t, handler, "after-cancel.example")
	if connections := proxy.connections.Load(); connections != 1 {
		t.Fatalf("stream cancellation discarded shared HTTP/2 carrier: connections=%d", connections)
	}
}

func TestHTTPSConnectStatusErrorKeepsSharedCarrier(t *testing.T) {
	proxy := newTestHTTPSProxy(t, true, "", "")
	handler := NewFromSettings("https-out", proxy.address(), map[string]any{"caFile": proxy.caFile})
	defer handler.Close()

	testTunnel(t, handler, "warm.example")
	rejected := "denied.example:443"
	proxy.rejectTarget.Store(&rejected)
	_, err := handler.Dial(context.Background(), bcnet.TCPDestination(bcnet.DomainAddress("denied.example"), 443))
	status, ok := err.(*StatusError)
	if !ok || status.StatusCode != http.StatusForbidden {
		t.Fatalf("denied target error = %T %v", err, err)
	}
	proxy.rejectTarget.Store(nil)
	testTunnel(t, handler, "after-denial.example")
	if connections := proxy.connections.Load(); connections != 1 {
		t.Fatalf("status response discarded shared HTTP/2 carrier: connections=%d", connections)
	}
}

func TestHTTPSConnectConcurrentFirstUseDoesNotRetireHealthyCarriers(t *testing.T) {
	proxy := newTestHTTPSProxy(t, true, "", "")
	handler := NewFromSettings("https-out", proxy.address(), map[string]any{"caFile": proxy.caFile})
	defer handler.Close()

	const count = 12
	start := make(chan struct{})
	results := make(chan net.Conn, count)
	errs := make(chan error, count)
	for index := 0; index < count; index++ {
		go func(index int) {
			<-start
			conn, err := handler.Dial(context.Background(), bcnet.TCPDestination(
				bcnet.DomainAddress("concurrent.example"), bcnet.Port(8000+index)))
			if err != nil {
				errs <- err
				return
			}
			results <- conn
		}(index)
	}
	close(start)
	var conns []net.Conn
	for index := 0; index < count; index++ {
		select {
		case err := <-errs:
			t.Fatal(err)
		case conn := <-results:
			conns = append(conns, conn)
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent CONNECT timed out")
		}
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	handler.cacheMu.Lock()
	retired := len(handler.retiredH2)
	handler.cacheMu.Unlock()
	if retired != 0 {
		t.Fatalf("concurrent healthy carriers retired = %d, want 0", retired)
	}
}

func TestHTTPSConnectRejectsBadCredentials(t *testing.T) {
	proxy := newTestHTTPSProxy(t, false, "user", "correct")
	handler := NewFromSettings("https-out", proxy.address(), map[string]any{
		"username":    "user",
		"password":    "wrong",
		"caFile":      proxy.caFile,
		"enableHTTP2": false,
	})
	defer handler.Close()
	_, err := handler.Dial(context.Background(), bcnet.TCPDestination(bcnet.DomainAddress("route.example"), 443))
	status, ok := err.(*StatusError)
	if !ok || status.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("bad credentials error = %T %v", err, err)
	}
}

func TestHTTPSConnectRejectsUDP(t *testing.T) {
	handler := NewFromSettings("https-out", "127.0.0.1:443", nil)
	_, err := handler.Dial(context.Background(), bcnet.UDPDestination(bcnet.DomainAddress("dns.example"), 53))
	if err == nil {
		t.Fatal("HTTPS CONNECT outbound accepted UDP")
	}
}

func TestHTTPSConnectRejectsInvalidDestination(t *testing.T) {
	handler := NewFromSettings("https-out", "127.0.0.1:443", nil)
	for _, destination := range []bcnet.Destination{
		{Network: bcnet.Network_TCP, Port: 443},
		bcnet.TCPDestination(bcnet.DomainAddress(""), 443),
		bcnet.TCPDestination(bcnet.DomainAddress("example.com"), 0),
		bcnet.TCPDestination(bcnet.DomainAddress("bad\r\nhost"), 443),
	} {
		if _, err := handler.Dial(context.Background(), destination); err == nil {
			t.Fatalf("HTTPS CONNECT accepted invalid destination: %#v", destination)
		}
	}
}
