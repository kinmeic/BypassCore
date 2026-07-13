// Package freedom implements the direct-connect outbound handler. It dials
// the destination directly (no proxy), optionally binding to a source IP or
// network interface (the "sendThrough" feature), and returns a net.Conn for
// the dispatcher to bridge.
//
// This replaces xray-core's proxy/freedom with a much simpler implementation:
// no fragmentation, no noise, no DNS override, no mux — just dial and connect.
package freedom

import (
	"context"
	"net"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
)

// Handler is a freedom (direct-connect) outbound dialer.
type Handler struct {
	tag       string
	bindIP    net.IP // source IP to dial from (sendThrough)
	bindIface string // network interface to bind to (Linux only)
}

// New creates a freedom handler.
//   tag: outbound tag (e.g. "direct", "wan1")
//   bindIP: source IP to dial from (empty = any)
//   bindIface: interface name to bind to (empty = any; Linux SO_BINDTODEVICE)
func New(tag, bindIP, bindIface string) *Handler {
	h := &Handler{tag: tag, bindIface: bindIface}
	if bindIP != "" {
		if ip := net.ParseIP(bindIP); ip != nil {
			h.bindIP = ip
		}
	}
	return h
}

// Tag returns the outbound tag.
func (h *Handler) Tag() string { return h.tag }

// Dial connects directly to the destination. The destination network (TCP/UDP)
// and address:port come from the routing decision.
func (h *Handler) Dial(ctx context.Context, dest bcnet.Destination) (net.Conn, error) {
	network := dest.Network.SystemString()
	address := dest.NetAddr()

	errors.LogInfo(ctx, "freedom[", h.tag, "] dialing ", network, "://", address)

	dialer := &net.Dialer{
		Timeout: 10 * time.Second, // default so unreachable hosts don't hang forever
	}
	if h.bindIP != nil {
		// Bind to source IP (sendThrough).
		if dest.Network == bcnet.Network_TCP {
			dialer.LocalAddr = &net.TCPAddr{IP: h.bindIP}
		} else if dest.Network == bcnet.Network_UDP {
			dialer.LocalAddr = &net.UDPAddr{IP: h.bindIP}
		}
	}

	// Bind to interface (Linux only, via SO_BINDTODEVICE). This must be done
	// BEFORE connect (in the Control callback) so the kernel selects the
	// correct egress interface for the route. Setting it post-connect has no
	// effect on the existing connection.
	if h.bindIface != "" {
		dialer.Control = makeBindControl(h.bindIface)
	}

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, errors.New("freedom dial failed: ", address).Base(err)
	}

	return conn, nil
}
