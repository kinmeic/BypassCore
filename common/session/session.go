// Package session provides connection metadata for routing decisions.
package session // import "github.com/eugene/bypasscore/common/session"

import (
	"github.com/eugene/bypasscore/common/net"
)

// MemoryUser is a minimal stand-in for protocol.MemoryUser. Routing only reads
// the Email field.
type MemoryUser struct {
	Email string
}

// Inbound is the metadata of an inbound connection.
type Inbound struct {
	// Source address of the inbound connection.
	Source net.Destination
	// Local address of the inbound connection.
	Local net.Destination
	// Tag of the inbound proxy that handles the connection.
	Tag string
	// Name of the inbound proxy that handles the connection.
	Name string
	// User authenticating the inbound. May be nil.
	User *MemoryUser
	// VlessRoute is the user-sent VLESS UUID's 7th<<8 | 8th bytes.
	VlessRoute net.Port
}

// Outbound is the metadata of an outbound connection.
type Outbound struct {
	// Target address of the outbound connection.
	OriginalTarget net.Destination
	Target         net.Destination
	RouteTarget    net.Destination
	// Tag of the outbound proxy that handles the connection.
	Tag string
	// Name of the outbound proxy that handles the connection.
	Name string
}

// Content is the metadata of the connection content. Mainly used for routing.
type Content struct {
	// Protocol of current content.
	Protocol string

	// HTTP traffic sniffed headers.
	Attributes map[string]string

	// SkipDNSResolve is set from DNS module to prevent cycle resolving.
	SkipDNSResolve bool
}

// SetAttribute attaches additional string attributes to content.
func (c *Content) SetAttribute(name string, value string) {
	if c.Attributes == nil {
		c.Attributes = make(map[string]string)
	}
	c.Attributes[name] = value
}

// Attribute retrieves additional string attributes from content.
func (c *Content) Attribute(name string) string {
	if c.Attributes == nil {
		return ""
	}
	return c.Attributes[name]
}
