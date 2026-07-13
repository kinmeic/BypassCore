package socks

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	bcnet "github.com/eugene/bypasscore/common/net"
)

// TestBuildConnectRequest_Domain verifies the SOCKS5 CONNECT request for a
// domain destination (ATYP=0x03).
func TestBuildConnectRequest_Domain(t *testing.T) {
	dest := bcnet.TCPDestination(bcnet.ParseAddress("example.com"), bcnet.Port(443))
	req, err := buildConnectRequest(dest)
	if err != nil {
		t.Fatalf("buildConnectRequest: %v", err)
	}
	// VER(1) CMD(1) RSV(1) ATYP(1) LEN(1) DOMAIN(11) PORT(2)
	if len(req) != 4+1+11+2 {
		t.Fatalf("req len = %d, want 18", len(req))
	}
	if req[0] != 0x05 {
		t.Errorf("VER = 0x%02x, want 0x05", req[0])
	}
	if req[1] != 0x01 {
		t.Errorf("CMD = 0x%02x, want 0x01 (CONNECT)", req[1])
	}
	if req[3] != 0x03 {
		t.Errorf("ATYP = 0x%02x, want 0x03 (domain)", req[3])
	}
	if int(req[4]) != len("example.com") {
		t.Errorf("domain len = %d, want %d", req[4], len("example.com"))
	}
	if string(req[5:16]) != "example.com" {
		t.Errorf("domain = %q, want example.com", string(req[5:16]))
	}
}

// TestBuildConnectRequest_IPv4 verifies ATYP=0x01 for an IPv4 destination.
func TestBuildConnectRequest_IPv4(t *testing.T) {
	dest := bcnet.TCPDestination(bcnet.ParseAddress("1.2.3.4"), bcnet.Port(8080))
	req, err := buildConnectRequest(dest)
	if err != nil {
		t.Fatalf("buildConnectRequest: %v", err)
	}
	// VER(1) CMD(1) RSV(1) ATYP(1) IP(4) PORT(2) = 10
	if len(req) != 10 {
		t.Fatalf("req len = %d, want 10", len(req))
	}
	if req[3] != 0x01 {
		t.Errorf("ATYP = 0x%02x, want 0x01 (IPv4)", req[3])
	}
	if string(req[4:8]) != string([]byte{1, 2, 3, 4}) {
		t.Errorf("IPv4 = %v, want [1 2 3 4]", req[4:8])
	}
}

// TestBuildConnectRequest_IPv6 verifies ATYP=0x04 for an IPv6 destination.
func TestBuildConnectRequest_IPv6(t *testing.T) {
	dest := bcnet.TCPDestination(bcnet.ParseAddress("::1"), bcnet.Port(443))
	req, err := buildConnectRequest(dest)
	if err != nil {
		t.Fatalf("buildConnectRequest: %v", err)
	}
	if req[3] != 0x04 {
		t.Errorf("ATYP = 0x%02x, want 0x04 (IPv6)", req[3])
	}
	if len(req) != 4+16+2 {
		t.Fatalf("req len = %d, want 22", len(req))
	}
}

// TestBuildConnectRequest_DomainTooLong rejects domains > 255 bytes.
func TestBuildConnectRequest_DomainTooLong(t *testing.T) {
	long := ""
	for i := 0; i < 256; i++ {
		long += "a"
	}
	dest := bcnet.TCPDestination(bcnet.DomainAddress(long), bcnet.Port(80))
	_, err := buildConnectRequest(dest)
	if err == nil {
		t.Error("domain > 255 should be rejected")
	}
}

// TestParseServer verifies host:port splitting and default port.
func TestParseServer(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"127.0.0.1:1080", "127.0.0.1", 1080},
		{"example.com:1080", "example.com", 1080},
		{"example.com", "example.com", 1080}, // default port
		{"[::1]:1080", "::1", 1080},
	}
	for _, c := range cases {
		gotHost, gotPort := ParseServer(c.in)
		if gotHost != c.host || gotPort != c.port {
			t.Errorf("ParseServer(%q) = (%q, %d), want (%q, %d)", c.in, gotHost, gotPort, c.host, c.port)
		}
	}
}

func TestParsePort(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"1080", 1080},
		{" 80 ", 80},
		{"abc", 1080},   // invalid → default
		{"-1", 1080},    // negative → default
		{"70000", 1080}, // out of range → default
	}
	for _, c := range cases {
		if got := parsePort(c.in); got != c.want {
			t.Errorf("parsePort(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestReplyCodeText verifies all known SOCKS5 reply codes have text.
func TestReplyCodeText(t *testing.T) {
	cases := []struct {
		code byte
		want string
	}{
		{0x00, "succeeded"},
		{0x01, "general SOCKS server failure"},
		{0x05, "connection refused"},
		{0x07, "command not supported"},
		{0xFF, "unknown error"},
	}
	for _, c := range cases {
		got := replyCodeText(c.code)
		if got != c.want {
			t.Errorf("replyCodeText(0x%02x) = %q, want %q", c.code, got, c.want)
		}
	}
}

func TestHandler_Dial_UDPAssociate(t *testing.T) {
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer udpLn.Close()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()

	go func() {
		conn, err := tcpLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		greeting := make([]byte, 3)
		_, _ = io.ReadFull(conn, greeting)
		_, _ = conn.Write([]byte{0x05, 0x00})
		request := make([]byte, 10)
		_, _ = io.ReadFull(conn, request)
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(udpLn.LocalAddr().(*net.UDPAddr).Port))
		response := append([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1}, port...)
		_, _ = conn.Write(response)
		buf := make([]byte, 65535)
		n, peer, err := udpLn.ReadFromUDP(buf)
		if err == nil {
			_, _ = udpLn.WriteToUDP(buf[:n], peer)
		}
		<-time.After(time.Second)
	}()

	h := New("test", tcpLn.Addr().String(), "", "")
	dest := bcnet.UDPDestination(bcnet.ParseAddress("1.2.3.4"), bcnet.Port(53))
	conn, err := h.Dial(context.Background(), dest)
	if err != nil {
		t.Fatalf("UDP associate: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("UDP payload = %q err=%v", buf[:n], err)
	}
}

// TestNewFromSettings verifies settings map extraction.
func TestNewFromSettings(t *testing.T) {
	settings := map[string]any{
		"username": "alice",
		"password": "secret",
	}
	h := NewFromSettings("test", "127.0.0.1:1080", settings)
	if h.username != "alice" || h.password != "secret" {
		t.Errorf("user/pass = %q/%q, want alice/secret", h.username, h.password)
	}
	if h.timeout == 0 {
		t.Error("timeout should be non-zero")
	}
}

// TestNewFromSettings_NilSettings verifies nil settings doesn't panic.
func TestNewFromSettings_NilSettings(t *testing.T) {
	h := NewFromSettings("test", "127.0.0.1:1080", nil)
	if h.username != "" || h.password != "" {
		t.Errorf("user/pass should be empty, got %q/%q", h.username, h.password)
	}
}
