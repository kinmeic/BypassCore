package dispatcher

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	bcnet "github.com/eugene/bypasscore/common/net"
	bcsession "github.com/eugene/bypasscore/common/session"
)

// TestSniff_Disabled_ReturnsConnUnchanged verifies that a disabled sniffer
// returns the same conn and no domain.
func TestSniff_Disabled_ReturnsConnUnchanged(t *testing.T) {
	s := NewSniffer(false)
	server, client := net.Pipe()
	defer server.Close()

	gotConn, domain := s.Sniff(client)
	if domain != "" {
		t.Errorf("disabled sniffer domain = %q, want empty", domain)
	}
	if gotConn != client {
		t.Error("disabled sniffer should return the same conn")
	}
	client.Close()
}

// TestSniff_TLS_SNI verifies SNI extraction from a real TLS ClientHello and
// confirms the returned conn replays the consumed bytes (P1-1 regression).
func TestSniff_TLS_SNI(t *testing.T) {
	// Use a plain TCP listener so the server-side conn receives raw bytes
	// (a tls.Listener would consume the ClientHello during its own handshake).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept the server-side conn.
	srvConnCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		srvConnCh <- c
	}()

	// Dial the server with SNI = "sni.example.com".
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Write a TLS ClientHello with SNI using tls.Client.
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "sni.example.com", InsecureSkipVerify: true})
	_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
	// The handshake writes the ClientHello. It will fail because the server
	// doesn't respond, but the ClientHello bytes are already on the wire.
	go func() { _ = tlsConn.Handshake() }()

	// Give the handshake write time to reach the server.
	time.Sleep(100 * time.Millisecond)

	srvConn := <-srvConnCh
	if srvConn == nil {
		t.Fatal("no server conn")
	}
	defer srvConn.Close()

	s := NewSniffer(true)
	wrappedConn, domain := s.Sniff(srvConn)
	if domain != "sni.example.com" {
		t.Fatalf("sniffed domain = %q, want sni.example.com", domain)
	}

	// P1-1 regression: verify the wrapped conn replays the consumed bytes.
	// The first byte of a TLS record is 0x16 (Handshake).
	buf := make([]byte, 1)
	n, err := wrappedConn.Read(buf)
	if err != nil || n != 1 {
		t.Fatalf("wrappedConn.Read: n=%d err=%v (bytes were lost!)", n, err)
	}
	if buf[0] != 0x16 {
		t.Errorf("first replayed byte = 0x%02x, want 0x16 (TLS handshake)", buf[0])
	}
}

// TestSniff_HTTP_Host verifies HTTP Host extraction + byte replay.
func TestSniff_HTTP_Host(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	// Write an HTTP request to the client side.
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	s := NewSniffer(true)
	// Small delay to let the write complete.
	time.Sleep(50 * time.Millisecond)
	wrappedConn, domain := s.Sniff(server)
	if domain != "example.com" {
		t.Fatalf("sniffed domain = %q, want example.com", domain)
	}

	// P1-1 regression: the wrapped conn must replay the HTTP request.
	buf := make([]byte, 3)
	n, err := wrappedConn.Read(buf)
	if err != nil || n != 3 {
		t.Fatalf("wrappedConn.Read: n=%d err=%v (bytes were lost!)", n, err)
	}
	if string(buf) != "GET" {
		t.Errorf("replayed bytes = %q, want 'GET'", string(buf))
	}
}

// TestSniff_HTTP_HostWithPort verifies port stripping from Host header.
func TestSniff_HTTP_HostWithPort(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"))
	}()
	time.Sleep(50 * time.Millisecond)

	s := NewSniffer(true)
	wrappedConn, domain := s.Sniff(server)
	if domain != "example.com" {
		t.Fatalf("sniffed domain = %q, want example.com (port stripped)", domain)
	}
	_ = wrappedConn
}

func TestSniff_HTTP_SegmentedHost(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHo"))
		time.Sleep(20 * time.Millisecond)
		_, _ = client.Write([]byte("st: segmented.example\r\n\r\n"))
	}()
	wrapped, domain, protocol := NewSniffer(true).SniffMetadata(server)
	if domain != "segmented.example" || protocol != "http" {
		t.Fatalf("segmented sniff = %q/%q", domain, protocol)
	}
	buf := make([]byte, len("GET / HTTP/1.1\r\nHost: segmented.example\r\n\r\n"))
	if _, err := io.ReadFull(wrapped, buf); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRoutingContext_RouteTargetPreservesOriginalIP(t *testing.T) {
	original := bcnet.TCPDestination(bcnet.ParseAddress("203.0.113.9"), 443)
	routeTarget := original
	routeTarget.Address = bcnet.ParseAddress("route.example")
	rctx := buildRoutingContext(context.Background(), &bcsession.Outbound{
		OriginalTarget: original,
		Target:         original,
		RouteTarget:    routeTarget,
	})
	if got := rctx.GetTargetDomain(); got != "route.example" {
		t.Fatalf("route domain = %q", got)
	}
	if got := rctx.GetTargetIPs(); len(got) != 1 || got[0].String() != "203.0.113.9" {
		t.Fatalf("target IPs = %v", got)
	}
}

// TestSniff_NoDomain_StillWraps verifies that when sniffing recovers no
// domain, the consumed bytes are still replayed (no data loss).
func TestSniff_NoDomain_StillWraps(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	go func() {
		_, _ = client.Write([]byte("NOT-TLS-NOT-HTTP some random data here"))
	}()
	time.Sleep(50 * time.Millisecond)

	s := NewSniffer(true)
	wrappedConn, domain := s.Sniff(server)
	if domain != "" {
		t.Errorf("domain = %q, want empty for unrecognized data", domain)
	}
	// Verify bytes are replayed.
	buf := make([]byte, 7)
	n, _ := wrappedConn.Read(buf)
	if n != 7 || string(buf) != "NOT-TLS" {
		t.Errorf("replayed = %q (n=%d), want 'NOT-TLS'", string(buf), n)
	}
}

// TestSniff_ReadTimeout verifies that a silent client (no data) does not
// block forever — the sniffer has a 4s deadline (P2-1 regression).
func TestSniff_ReadTimeout(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	s := NewSniffer(true)
	start := time.Now()
	wrappedConn, domain := s.Sniff(server)
	elapsed := time.Since(start)

	if domain != "" {
		t.Errorf("domain = %q, want empty", domain)
	}
	// Should have returned within the 4s timeout (allow some margin).
	if elapsed > 6*time.Second {
		t.Fatalf("Sniff blocked for %v, expected <=4s timeout", elapsed)
	}
	if elapsed < 3*time.Second {
		t.Logf("note: Sniff returned quickly (%v) — possibly an immediate error", elapsed)
	}
	_ = wrappedConn
}

// TestPrependConn_Read verifies the prependConn replays buffer then reads
// from the underlying conn.
func TestPrependConn_Read(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Prepend "HELLO" then read from the pipe.
	pc := &prependConn{Conn: server, buf: []byte("HELLO")}

	// First reads return the buffer.
	buf := make([]byte, 5)
	n, _ := pc.Read(buf)
	if n != 5 || string(buf) != "HELLO" {
		t.Fatalf("first read = %q (n=%d), want HELLO", string(buf), n)
	}

	// After buffer is drained, reads come from the underlying conn.
	go func() { _, _ = client.Write([]byte("WORLD")) }()
	buf2 := make([]byte, 5)
	n2, _ := pc.Read(buf2)
	if n2 != 5 || string(buf2) != "WORLD" {
		t.Fatalf("second read = %q (n=%d), want WORLD", string(buf2), n2)
	}
}

// TestPrependConn_SatisfiesNetConn is a compile-time check.
func TestPrependConn_SatisfiesNetConn(t *testing.T) {
	var _ net.Conn = (*prependConn)(nil)
	var _ io.Reader = (*prependConn)(nil)
}
