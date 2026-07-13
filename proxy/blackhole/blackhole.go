// Package blackhole implements the drop outbound handler. It accepts a
// connection but immediately closes it, effectively blocking the traffic.
package blackhole

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
)

// Handler is a blackhole (drop) outbound dialer.
type Handler struct {
	tag string
}

// New creates a blackhole handler.
func New(tag string) *Handler {
	return &Handler{tag: tag}
}

// Tag returns the outbound tag.
func (h *Handler) Tag() string { return h.tag }

// Dial returns a discard connection, effectively dropping the traffic.
// The returned net.Conn accepts writes (discarding them) and returns EOF
// on read, so transport.Bridge cleanly closes the inbound side without
// logging spurious errors.
func (h *Handler) Dial(_ context.Context, dest bcnet.Destination) (net.Conn, error) {
	errors.LogInfo(context.Background(), "blackhole[", h.tag, "] dropping ", dest.String())
	return &discardConn{}, nil
}

// discardConn is a net.Conn that discards all writes and signals EOF on read.
// This is the correct sink for a blackhole: io.Copy treats io.EOF as a
// normal completion, so Bridge returns nil (not an error) and the inbound
// side is cleanly closed.
type discardConn struct{}

func (*discardConn) Read([]byte) (int, error)          { return 0, io.EOF }
func (*discardConn) Write(p []byte) (int, error)       { return len(p), nil }
func (*discardConn) Close() error                      { return nil }
func (*discardConn) LocalAddr() net.Addr               { return &net.IPAddr{} }
func (*discardConn) RemoteAddr() net.Addr              { return &net.IPAddr{} }
func (*discardConn) SetDeadline(t time.Time) error     { return nil }
func (*discardConn) SetReadDeadline(t time.Time) error  { return nil }
func (*discardConn) SetWriteDeadline(t time.Time) error { return nil }
