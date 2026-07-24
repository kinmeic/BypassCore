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
