// Package blackhole implements the drop outbound handler. It accepts a
// connection but immediately closes it, effectively blocking the traffic.
package blackhole

import (
	"context"
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

// Dial returns a closed connection, effectively dropping the traffic.
// The returned net.Conn is immediately useless (already closed), so
// transport.Bridge will copy nothing and close the inbound side.
func (h *Handler) Dial(_ context.Context, dest bcnet.Destination) (net.Conn, error) {
	errors.LogInfo(context.Background(), "blackhole[", h.tag, "] dropping ", dest.String())
	// Return a closed pipe — Bridge will see EOF and close the inbound.
	return &closedConn{}, nil
}

// closedConn is a net.Conn that is already closed. Reads return EOF, writes
// return an error.
type closedConn struct{}

func (*closedConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*closedConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (*closedConn) Close() error                      { return nil }
func (*closedConn) LocalAddr() net.Addr               { return &net.IPAddr{} }
func (*closedConn) RemoteAddr() net.Addr              { return &net.IPAddr{} }
func (*closedConn) SetDeadline(t time.Time) error   { return nil }
func (*closedConn) SetReadDeadline(t time.Time) error  { return nil }
func (*closedConn) SetWriteDeadline(t time.Time) error { return nil }
