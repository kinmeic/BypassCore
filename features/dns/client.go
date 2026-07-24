// Package dns defines the DNS client interface used by routing.
package dns // import "github.com/eugene/bypasscore/features/dns"

import (
	"context"
	"fmt"

	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/features"
)

// IPOption is an object for IP query options.
type IPOption struct {
	IPv4Enable bool
	IPv6Enable bool
	FakeEnable bool
}

// Client is a feature for querying DNS information.
type Client interface {
	features.Feature
	// LookupIP returns IP addresses for the given domain.
	LookupIP(domain string, option IPOption) ([]net.IP, uint32, error)
}

// ContextClient is implemented by DNS clients that can cancel an in-flight
// lookup when its caller disconnects or the listener shuts down.
type ContextClient interface {
	Client
	LookupIPContext(ctx context.Context, domain string, option IPOption) ([]net.IP, uint32, error)
}

// TaggedContextClient allows control-plane diagnostics to select one
// configured DNS server without changing normal domain-policy ordering.
type TaggedContextClient interface {
	ContextClient
	LookupIPByServerTagContext(ctx context.Context, serverTag, domain string, option IPOption) ([]net.IP, uint32, error)
}

// RawContextClient is implemented by DNS clients that can forward an arbitrary
// DNS wire-format query. It is used by the native DNS inbound for record types
// which cannot be represented by LookupIP, such as MX, TXT, SRV, PTR and CAA.
type RawContextClient interface {
	ContextClient
	LookupRawContext(ctx context.Context, domain string, query []byte) ([]byte, error)
}

// ClientType returns the type of Client interface.
func ClientType() interface{} {
	return (*Client)(nil)
}

// ErrEmptyResponse indicates that DNS query succeeded but no answer was returned.
var ErrEmptyResponse = errors.New("empty response")

const DefaultTTL = 300

// RCodeError wraps a DNS response code (RFC 6895) as an error.
type RCodeError uint16

// Error implements error.
func (e RCodeError) Error() string {
	return fmt.Sprint("rcode: ", uint16(e))
}

// String implements fmt.Stringer.
func (e RCodeError) String() string { return e.Error() }

// IP implements net.Address. Always panics: an RCode is not an IP.
func (RCodeError) IP() net.IP { panic("Calling IP() on a RCodeError.") }

// Domain implements net.Address. Always panics: an RCode is not a domain.
func (RCodeError) Domain() string { panic("Calling Domain() on a RCodeError.") }

// Family implements net.Address. Always panics: an RCode is not an address.
func (RCodeError) Family() net.AddressFamily { panic("Calling Family() on a RCodeError.") }

// RCodeFromError extracts the RCode from an error chain (unwrapping Cause).
func RCodeFromError(err error) uint16 {
	if err == nil {
		return 0
	}
	cause := errors.Cause(err)
	if r, ok := cause.(RCodeError); ok {
		return uint16(r)
	}
	return 0
}
