package blackhole

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	bcnet "github.com/eugene/bypasscore/common/net"
)

// TestBlackhole_Tag verifies the tag is returned correctly.
func TestBlackhole_Tag(t *testing.T) {
	h := New("block")
	if got := h.Tag(); got != "block" {
		t.Errorf("Tag() = %q, want block", got)
	}
}

// TestBlackhole_Dial_ReturnsDiscardConn verifies Dial returns a non-nil conn.
func TestBlackhole_Dial_ReturnsDiscardConn(t *testing.T) {
	h := New("block")
	dest := bcnet.TCPDestination(bcnet.ParseAddress("1.2.3.4"), bcnet.Port(80))
	conn, err := h.Dial(context.Background(), dest)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if conn == nil {
		t.Fatal("Dial returned nil conn")
	}
	defer conn.Close()
}

// TestDiscardConn_WriteAccepts verifies Write accepts and discards data
// (returns len(p), nil) — P1-3 regression: previously returned ErrClosed.
func TestDiscardConn_WriteAccepts(t *testing.T) {
	c := &discardConn{}
	n, err := c.Write([]byte("hello world"))
	if err != nil {
		t.Errorf("Write err = %v, want nil (should discard)", err)
	}
	if n != 11 {
		t.Errorf("Write n = %d, want 11", n)
	}
}

// TestDiscardConn_ReadReturnsEOF verifies Read returns io.EOF — P1-3
// regression: previously returned net.ErrClosed, causing transport.Bridge
// to log a spurious error.
func TestDiscardConn_ReadReturnsEOF(t *testing.T) {
	c := &discardConn{}
	n, err := c.Read(make([]byte, 100))
	if err != io.EOF {
		t.Errorf("Read err = %v, want io.EOF", err)
	}
	if n != 0 {
		t.Errorf("Read n = %d, want 0", n)
	}
}

// TestDiscardConn_SatisfiesNetConn is a compile-time check.
func TestDiscardConn_SatisfiesNetConn(t *testing.T) {
	var _ net.Conn = (*discardConn)(nil)
}

// TestBlackhole_BridgeIntegration simulates what transport.Bridge does with
// a blackhole conn: copy from a source to the discard conn and from the
// discard conn to a sink. io.Copy must treat io.EOF as normal completion.
func TestBlackhole_BridgeIntegration(t *testing.T) {
	src := &stringConn{data: []byte("some data to discard"), closed: false}
	dst := &discardConn{}

	// io.Copy(dst, src) should complete without error (Write discards).
	n, err := io.Copy(dst, src)
	if err != nil {
		t.Errorf("io.Copy to discard: %v", err)
	}
	if n != 20 {
		t.Errorf("io.Copy n = %d, want 20", n)
	}

	// io.Copy(sink, discardConn) should complete with EOF (no error).
	sink := &byteBufConn{}
	n2, err2 := io.Copy(sink, dst)
	if err2 != nil {
		t.Errorf("io.Copy from discard: %v", err2)
	}
	if n2 != 0 {
		t.Errorf("io.Copy from discard n = %d, want 0", n2)
	}
}

// stringConn is a minimal net.Conn for testing io.Copy from a data source.
type stringConn struct {
	data   []byte
	closed bool
	net.Conn
}

func (s *stringConn) Read(p []byte) (int, error) {
	if len(s.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.data)
	s.data = s.data[n:]
	return n, nil
}
func (s *stringConn) Write(p []byte) (int, error) { return len(p), nil }
func (s *stringConn) Close() error                { s.closed = true; return nil }
func (s *stringConn) LocalAddr() net.Addr         { return &net.IPAddr{} }
func (s *stringConn) RemoteAddr() net.Addr        { return &net.IPAddr{} }
func (s *stringConn) SetDeadline(t time.Time) error { return nil }
func (s *stringConn) SetReadDeadline(t time.Time) error { return nil }
func (s *stringConn) SetWriteDeadline(t time.Time) error { return nil }

// byteBufConn collects written bytes for assertions.
type byteBufConn struct {
	buf []byte
	net.Conn
}

func (c *byteBufConn) Read(p []byte) (int, error) { return 0, io.EOF }
func (c *byteBufConn) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	return len(p), nil
}
func (c *byteBufConn) Close() error                     { return nil }
func (c *byteBufConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (c *byteBufConn) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (c *byteBufConn) SetDeadline(t time.Time) error { return nil }
func (c *byteBufConn) SetReadDeadline(t time.Time) error { return nil }
func (c *byteBufConn) SetWriteDeadline(t time.Time) error { return nil }
