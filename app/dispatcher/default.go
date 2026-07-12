// Package dispatcher is the data-plane hub: it receives a connection from
// an inbound listener, optionally sniffs the protocol/domain, routes it via
// the routing engine, and bridges it to the chosen outbound handler.
//
// Flow:
//   inbound conn → (sniff TLS/HTTP) → router.PickRoute → outboundTag
//   → outbound.Handler.Dial(ctx, dest) → transport.Bridge(inbound, outbound)
package dispatcher

import (
	"context"
	"net"

	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	bcsession "github.com/eugene/bypasscore/common/session"
	"github.com/eugene/bypasscore/features/routing"
	routingsession "github.com/eugene/bypasscore/features/routing/session"
	"github.com/eugene/bypasscore/app/dialer"
	"github.com/eugene/bypasscore/transport"
)


// Dispatcher routes accepted connections to outbound handlers.
type Dispatcher struct {
	router  routing.Router
	ohm     DialerManager
	sniffer *Sniffer
}

// DialerManager looks up a Dialer by tag.
type OutboundManager interface {
	GetDialer(tag string) dialer.Dialer
	GetDefaultDialer() dialer.Dialer
}

// New creates a Dispatcher.
func New(router routing.Router, ohm DialerManager, sniffer *Sniffer) *Dispatcher {
	return &Dispatcher{
		router:  router,
		ohm:     ohm,
		sniffer: sniffer,
	}
}

// Dispatch handles a single accepted inbound connection. It blocks until the
// connection is closed (both directions copied). The caller (inbound listener)
// should invoke this in a goroutine.
//
// dest is the original destination (from tproxy SO_ORIGINAL_DST / redirect).
// conn is the accepted TCP connection.
func (d *Dispatcher) Dispatch(ctx context.Context, conn net.Conn, dest bcnet.Destination) error {
	// Build a routing context from the session.
	rctx := buildRoutingContext(ctx, dest)

	// Sniff the first bytes to recover the domain (if enabled).
	if d.sniffer != nil {
		if sniffed := d.sniffer.Sniff(conn); sniffed != "" {
			errors.LogInfo(ctx, "sniffed domain: ", sniffed, " for ", dest.String())
			// Override destination address with sniffed domain.
			dest.Address = bcnet.ParseAddress(sniffed)
			rctx = buildRoutingContext(ctx, dest)
		}
	}

	// Route: ask the router which outbound tag to use.
	route, err := d.router.PickRoute(rctx)
	var outTag string
	if err != nil {
		errors.LogInfoInner(ctx, err, "no matching route, using default outbound")
		// Fall back to default handler.
		dialer := d.ohm.GetDefaultDialer()
		if dialer == nil {
			conn.Close()
			return errors.New("no default outbound available")
		}
		outTag = dialer.Tag()
		return d.bridge(ctx, conn, dialer, dest)
	}
	outTag = route.GetOutboundTag()
	errors.LogInfo(ctx, "route: ", dest.String(), " → ", outTag)

	// Look up the outbound dialer.
	dialer := d.ohm.GetDialer(outTag)
	if dialer == nil {
		dialer = d.ohm.GetDefaultDialer()
		if dialer == nil {
			conn.Close()
			return errors.New("outbound ", outTag, " not found and no default")
		}
	}

	return d.bridge(ctx, conn, dialer, dest)
}

// bridge dials the outbound and copies data bidirectionally.
func (d *Dispatcher) bridge(ctx context.Context, inbound net.Conn, dialer dialer.Dialer, dest bcnet.Destination) error {
	outbound, err := dialer.Dial(ctx, dest)
	if err != nil {
		inbound.Close()
		return errors.New("outbound dial failed for ", dest.String()).Base(err)
	}

	// Bidirectional copy until either side closes.
	err = transport.Bridge(inbound, outbound)
	inbound.Close()
	outbound.Close()
	return err
}

// buildRoutingContext creates a routing.Context from the session info and
// destination.
func buildRoutingContext(ctx context.Context, dest bcnet.Destination) routing.Context {
	return &routingsession.Context{
		Outbound: &bcsession.Outbound{
			Target: dest,
		},
		Content: bcsession.ContentFromContext(ctx),
	}
}

// DialerManager looks up a Dialer by tag.
type DialerManager interface {
	GetDialer(tag string) dialer.Dialer
	GetDefaultDialer() dialer.Dialer
}

// DialOutbound routes the destination via the router and dials the chosen
// outbound. It's used by the UDP tproxy listener which can't use Dispatch
// (Dispatch is stream-oriented, not packet-oriented).
//
// The returned net.Conn is a raw TCP/UDP connection to the outbound; the
// caller manages I/O directly.
func (d *Dispatcher) DialOutbound(ctx context.Context, dest bcnet.Destination) (net.Conn, error) {
	// Build routing context.
	rctx := buildRoutingContext(ctx, dest)

	// Route.
	route, err := d.router.PickRoute(rctx)
	var dialer dialer.Dialer
	if err != nil {
		// Fall back to default.
		dialer = d.ohm.GetDefaultDialer()
		if dialer == nil {
			return nil, errors.New("no default outbound available")
		}
	} else {
		outTag := route.GetOutboundTag()
		dialer = d.ohm.GetDialer(outTag)
		if dialer == nil {
			dialer = d.ohm.GetDefaultDialer()
		}
	}

	if dialer == nil {
		return nil, errors.New("no outbound available")
	}

	return dialer.Dial(ctx, dest)
}
