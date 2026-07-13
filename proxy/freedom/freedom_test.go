package freedom

import (
	"context"
	"net"
	"testing"
	"time"

	bcnet "github.com/eugene/bypasscore/common/net"
)

// TestNew_Defaults verifies the constructor sets fields correctly.
func TestNew_Defaults(t *testing.T) {
	h := New("direct", "", "")
	if h.tag != "direct" {
		t.Errorf("tag = %q, want direct", h.tag)
	}
	if h.bindIP != nil {
		t.Error("bindIP should be nil for empty string")
	}
	if h.bindIface != "" {
		t.Error("bindIface should be empty")
	}
}

// TestNew_WithBindIP verifies IP parsing.
func TestNew_WithBindIP(t *testing.T) {
	h := New("wan1", "192.168.1.2", "")
	if h.bindIP == nil || !h.bindIP.Equal(net.ParseIP("192.168.1.2")) {
		t.Errorf("bindIP = %v, want 192.168.1.2", h.bindIP)
	}
}

// TestNew_InvalidBindIP verifies invalid IP is silently ignored.
func TestNew_InvalidBindIP(t *testing.T) {
	h := New("wan1", "not-an-ip", "")
	if h.bindIP != nil {
		t.Error("invalid bindIP should be nil")
	}
}

// TestNew_WithInterface verifies interface name is stored.
func TestNew_WithInterface(t *testing.T) {
	h := New("wan1", "192.168.1.2", "en0")
	if h.bindIface != "en0" {
		t.Errorf("bindIface = %q, want en0", h.bindIface)
	}
}

// TestTag verifies Tag().
func TestTag(t *testing.T) {
	h := New("mytag", "", "")
	if got := h.Tag(); got != "mytag" {
		t.Errorf("Tag() = %q, want mytag", got)
	}
}

// TestDial_LocalConnection verifies Dial connects to a real listener and
// returns a working conn.
func TestDial_LocalConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 5)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("hello"))
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	h := New("direct", "", "")
	dest := bcnet.TCPDestination(bcnet.ParseAddress("127.0.0.1"), bcnet.Port(port))

	conn, err := h.Dial(context.Background(), dest)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("test\n"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 5)
	_, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("Read = %q, want hello", string(buf))
	}
}

// TestDial_Unreachable verifies Dial fails on an unreachable port (with the
// default 10s timeout, this should fail quickly with connection refused).
func TestDial_Unreachable(t *testing.T) {
	// Port 1 is reserved and almost always closed.
	h := New("direct", "", "")
	dest := bcnet.TCPDestination(bcnet.ParseAddress("127.0.0.1"), bcnet.Port(1))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := h.Dial(ctx, dest)
	if err == nil {
		t.Error("Dial to port 1 should fail")
	}
}
