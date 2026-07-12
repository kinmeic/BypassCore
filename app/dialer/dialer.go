// Package dialer defines the Dialer interface used by the data plane. Both
// proxy/freedom and proxy/blackhole implement it; app/outbound's Manager
// returns it via GetDialer; app/dispatcher consumes it.
//
// This package exists to break the would-be import cycle:
// dispatcher → outbound → proxy/freedom → (no cycle, but outbound can't
// import dispatcher). By placing the interface in a leaf package, all three
// can reference it without importing each other.
package dialer

import (
	"context"
	"net"

	bcnet "github.com/eugene/bypasscore/common/net"
)

// Dialer dials a connection to the given destination.
type Dialer interface {
	// Dial connects to dest and returns a net.Conn for bidirectional copying.
	Dial(ctx context.Context, dest bcnet.Destination) (net.Conn, error)
	// Tag returns the outbound tag.
	Tag() string
}
