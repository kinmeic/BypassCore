// Package dispatcher is the data-plane hub: it receives a connection from
// an inbound listener, optionally sniffs the protocol/domain, routes it via
// the routing engine, and bridges it to the chosen outbound handler.
//
// Flow:
//
//	inbound conn → (sniff TLS/HTTP) → router.PickRoute → outboundTag
//	→ outbound.Handler.Dial(ctx, dest) → transport.Bridge(inbound, outbound)
package dispatcher

import (
	"context"
	stderrors "errors"
	"net"

	"github.com/eugene/bypasscore/app/dialer"
	"github.com/eugene/bypasscore/common"
	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	httpproto "github.com/eugene/bypasscore/common/protocol/http"
	bcsession "github.com/eugene/bypasscore/common/session"
	"github.com/eugene/bypasscore/features/routing"
	routingsession "github.com/eugene/bypasscore/features/routing/session"
	"github.com/eugene/bypasscore/transport"
)

// Dispatcher routes accepted connections to outbound handlers.
type Dispatcher struct {
	router  routing.Router
	ohm     DialerManager
	sniffer *Sniffer
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
	originalDest := dest
	content := bcsession.ContentFromContext(ctx)
	if content == nil {
		content = new(bcsession.Content)
		ctx = bcsession.ContextWithContent(ctx, content)
	}
	outboundSession := &bcsession.Outbound{OriginalTarget: originalDest, Target: originalDest}

	// Sniff the first bytes to recover the domain (if enabled).
	// Sniff returns a new conn that replays the consumed bytes, so the
	// outbound stream is not truncated.
	if d.sniffer != nil {
		var sniffed, protocol string
		conn, sniffed, protocol = d.sniffer.SniffMetadata(conn)
		content.Protocol = protocol
		if protocol == "http" {
			if replay, ok := conn.(*prependConn); ok {
				_, content.Attributes = httpproto.SniffRequest(replay.buf)
			}
		}
		if sniffed != "" {
			errors.LogDebug(ctx, "sniffed domain: ", sniffed, " for ", dest.String())
			// Match Xray's routeOnly semantics: the untrusted SNI/Host is used for
			// routing, while the actual dial target remains the kernel-recovered
			// original destination.
			routeDest := originalDest
			routeDest.Address = bcnet.ParseAddress(sniffed)
			outboundSession.RouteTarget = routeDest
		}
	}
	rctx := buildRoutingContext(ctx, outboundSession)

	// Route: ask the router which outbound tag to use.
	route, err := d.router.PickRoute(rctx)
	var outTag string
	if err != nil {
		if !stderrors.Is(err, common.ErrNoClue) {
			_ = conn.Close()
			return errors.New("routing failed for ", dest.String()).Base(err)
		}
		errors.LogInfoInner(ctx, err, "no matching route, using default outbound")
		// Fall back to default handler.
		dialer := d.ohm.GetDefaultDialer()
		if dialer == nil {
			conn.Close()
			return errors.New("no default outbound available")
		}
		return d.bridge(ctx, conn, dialer, originalDest)
	}
	outTag = route.GetOutboundTag()
	errors.LogDebug(ctx, "route: ", dest.String(), " → ", outTag)

	// Look up the outbound dialer.
	dialer := d.ohm.GetDialer(outTag)
	if dialer == nil {
		conn.Close()
		return errors.New("routed outbound ", outTag, " not found")
	}

	return d.bridge(ctx, conn, dialer, originalDest)
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
func buildRoutingContext(ctx context.Context, outbound *bcsession.Outbound) routing.Context {
	return &routingsession.Context{
		Inbound:  bcsession.InboundFromContext(ctx),
		Outbound: outbound,
		Content:  bcsession.ContentFromContext(ctx),
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
	return d.dialOutboundPackets(ctx, dest, nil)
}

// DialOutboundPackets applies UDP protocol/domain sniffing before routing but
// keeps the kernel-recovered IP as the actual dial target (routeOnly).
func (d *Dispatcher) DialOutboundPackets(ctx context.Context, dest bcnet.Destination, packets [][]byte) (net.Conn, error) {
	return d.dialOutboundPackets(ctx, dest, packets)
}

// SniffPacketMetadata exposes the bounded packet sniffer to the UDP session so
// it can collect another Initial packet only when the parser asks for it.
func (d *Dispatcher) SniffPacketMetadata(packets [][]byte) (string, string, bool) {
	if d.sniffer == nil {
		return "", "", false
	}
	return d.sniffer.SniffPacketMetadata(packets)
}

func (d *Dispatcher) dialOutboundPackets(ctx context.Context, dest bcnet.Destination, packets [][]byte) (net.Conn, error) {
	// Build routing context.
	outboundSession := &bcsession.Outbound{OriginalTarget: dest, Target: dest}
	if domain, protocol, _ := d.SniffPacketMetadata(packets); domain != "" {
		routeDest := dest
		routeDest.Address = bcnet.ParseAddress(domain)
		outboundSession.RouteTarget = routeDest
		content := bcsession.ContentFromContext(ctx)
		if content == nil {
			content = new(bcsession.Content)
			ctx = bcsession.ContextWithContent(ctx, content)
		}
		content.Protocol = protocol
		errors.LogDebug(ctx, "sniffed UDP domain: ", domain, " for ", dest.String())
	}
	rctx := buildRoutingContext(ctx, outboundSession)

	// Route.
	route, err := d.router.PickRoute(rctx)
	var dialer dialer.Dialer
	if err != nil {
		if !stderrors.Is(err, common.ErrNoClue) {
			return nil, errors.New("routing failed for ", dest.String()).Base(err)
		}
		// Fall back to default.
		dialer = d.ohm.GetDefaultDialer()
		if dialer == nil {
			return nil, errors.New("no default outbound available")
		}
	} else {
		outTag := route.GetOutboundTag()
		dialer = d.ohm.GetDialer(outTag)
		if dialer == nil {
			return nil, errors.New("routed outbound ", outTag, " not found")
		}
	}

	if dialer == nil {
		return nil, errors.New("no outbound available")
	}

	return dialer.Dial(ctx, dest)
}
