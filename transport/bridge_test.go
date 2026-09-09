package transport

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestBridge_DataTransfer verifies data flows bidirectionally through real
// TCP connections that support CloseWrite (half-close).
func TestBridge_DataTransfer(t *testing.T) {
	ln1, _ := net.Listen("tcp", "127.0.0.1:0")
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln1.Close()
	defer ln2.Close()

	// Dial client1 → inbound(ln1), client2 → outbound(ln2).
	client1, _ := net.Dial("tcp", ln1.Addr().String())
	client2, _ := net.Dial("tcp", ln2.Addr().String())
	defer client1.Close()
	defer client2.Close()

	inbound, _ := ln1.Accept()
	outbound, _ := ln2.Accept()
	defer inbound.Close()
	defer outbound.Close()

	// Start the bridge.
	done := make(chan error, 1)
	go func() {
		done <- Bridge(inbound, outbound)
	}()

	// Write to client1 → flows through inbound → bridge → outbound → client2.
	go func() {
		_, _ = client1.Write([]byte("hello"))
		client1.(*net.TCPConn).CloseWrite()
	}()

	buf := make([]byte, 5)
	_ = client2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client2.Read(buf)
	if err != nil || n != 5 {
		t.Fatalf("client2 Read: n=%d err=%v", n, err)
	}
	if string(buf) != "hello" {
		t.Errorf("got %q, want hello", string(buf))
	}

	// Close both sides to let Bridge complete.
	client2.Close()
	outbound.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Bridge did not complete")
	}
}

// TestBridge_BothClosedReturns verifies Bridge completes when both conns
// are closed.
func TestBridge_BothClosedReturns(t *testing.T) {
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		_ = Bridge(a, b)
		close(done)
	}()
	_ = a.Close()
	_ = b.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Bridge did not complete after both closed")
	}
}

func TestBridgeOneSidedEOFWithoutHalfCloseDrainsReverseData(t *testing.T) {
	a, peerA := net.Pipe()
	b, peerB := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Bridge(a, b) }()
	go func() {
		_, _ = peerB.Write([]byte("final"))
		_ = peerB.Close()
	}()
	buffer := make([]byte, 5)
	if _, err := io.ReadFull(peerA, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "final" {
		t.Fatalf("reverse data = %q, want final", buffer)
	}
	_ = peerA.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Bridge did not finish after both directions drained")
	}
}

// TestBridgeIdleTimeoutEvictsSilentTunnel verifies a tunnel with no traffic
// in either direction is closed after the idle timeout, and both bridge-side
// conns are closed so the peers observe the eviction.
func TestBridgeIdleTimeoutEvictsSilentTunnel(t *testing.T) {
	a, peerA := net.Pipe()
	b, peerB := net.Pipe()
	defer peerA.Close()
	defer peerB.Close()

	done := make(chan error, 1)
	go func() { done <- BridgeWithIdleTimeout(a, b, 50*time.Millisecond) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Bridge returned %v, want nil on idle eviction", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Bridge did not evict a silent tunnel")
	}

	if _, err := a.Write([]byte("x")); err == nil {
		t.Error("bridge side a still writable after idle eviction")
	}
	if _, err := b.Write([]byte("x")); err == nil {
		t.Error("bridge side b still writable after idle eviction")
	}
}

// TestBridgeIdleTimeoutRefreshesOnActivity verifies traffic in one direction
// keeps the whole tunnel alive (a one-way stream must not be evicted), and
// eviction happens once traffic stops.
func TestBridgeIdleTimeoutRefreshesOnActivity(t *testing.T) {
	a, peerA := net.Pipe()
	b, peerB := net.Pipe()
	defer peerA.Close()
	defer peerB.Close()

	done := make(chan error, 1)
	go func() { done <- BridgeWithIdleTimeout(a, b, 100*time.Millisecond) }()

	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if _, err := peerA.Write([]byte("k")); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		buf := make([]byte, 16)
		for {
			if _, err := peerB.Read(buf); err != nil {
				return
			}
		}
	}()

	select {
	case err := <-done:
		t.Fatalf("Bridge evicted an active tunnel: %v", err)
	case <-time.After(250 * time.Millisecond):
	}

	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Bridge returned %v, want nil on idle eviction", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Bridge did not evict after traffic stopped")
	}
}

// TestBridgeDisabledIdleTimeoutKeepsSilentTunnel verifies a non-positive
// timeout preserves the original wait-forever semantics.
func TestBridgeDisabledIdleTimeoutKeepsSilentTunnel(t *testing.T) {
	a, peerA := net.Pipe()
	b, peerB := net.Pipe()
	defer peerA.Close()
	defer peerB.Close()

	done := make(chan error, 1)
	go func() { done <- BridgeWithIdleTimeout(a, b, 0) }()

	select {
	case err := <-done:
		t.Fatalf("Bridge with disabled idle timeout returned early: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	_ = peerA.Close()
	_ = peerB.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Bridge did not finish after peers closed")
	}
}

func TestConnIdleTimeoutContext(t *testing.T) {
	if got := ConnIdleTimeoutFromContext(t.Context()); got != DefaultConnIdleTimeout {
		t.Fatalf("unset context: got %v, want default %v", got, DefaultConnIdleTimeout)
	}
	ctx := ContextWithConnIdleTimeout(t.Context(), 42*time.Second)
	if got := ConnIdleTimeoutFromContext(ctx); got != 42*time.Second {
		t.Fatalf("override context: got %v, want 42s", got)
	}
}

// TestNewConnLink verifies the Link wrapper reads through the conn.
func TestNewConnLink(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	link := NewConnLink(server)

	go func() {
		_, _ = client.Write([]byte("test"))
		client.Close()
	}()

	buf := make([]byte, 4)
	n, err := link.Reader.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}
	if n != 4 || string(buf) != "test" {
		t.Errorf("Read = %q (n=%d), want 'test'", string(buf), n)
	}
}

// TestConnRWC_Close verifies Close propagates to the underlying conn.
func TestConnRWC_Close(t *testing.T) {
	server, client := net.Pipe()
	c := &connRWC{Conn: server}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	_, err := client.Write([]byte("x"))
	if err == nil {
		t.Error("write after close should fail")
	}
}

var _ = sync.WaitGroup{}
