package routing

import (
	"github.com/eugene/bypasscore/features"
)

// Dispatcher is a feature that dispatches inbound requests to outbound handlers.
// In BypassCore the routing subsystem exposes the routing-decision surface
// (Router.PickRoute); the actual connection Dispatch is the upper layer's job.
// The Dispatcher interface is retained for API compatibility but its methods
// are intentionally minimal — the proxy forwarding stack (transport.Link) is
// out of scope for the split-routing engine.
//
type Dispatcher interface {
	features.Feature
}

// DispatcherType returns the type of Dispatcher interface.
func DispatcherType() interface{} {
	return (*Dispatcher)(nil)
}
