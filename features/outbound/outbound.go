// Package outbound defines the outbound manager interfaces used by routing.
package outbound // import "github.com/eugene/bypasscore/features/outbound"

import (
	"context"

	"github.com/eugene/bypasscore/features"
)

// Handler is the interface for outbound handlers. For routing purposes a
// handler only needs to identify itself by tag.
type Handler interface {
	features.Feature
	Tag() string
}

// HandlerSelector selects outbound tags matching the given selectors.
// A selector matches by prefix (see app/outbound.Manager.Select).
type HandlerSelector interface {
	Select(selectors []string) []string
}

// Manager is a feature that manages outbound handlers.
type Manager interface {
	features.Feature
	// GetHandler returns the Handler for the given tag.
	GetHandler(tag string) Handler
	// GetDefaultHandler returns the default handler (usually the first registered).
	GetDefaultHandler() Handler
}

// ManagerType returns the type of Manager interface.
func ManagerType() interface{} {
	return (*Manager)(nil)
}

// Used by observatory/App to add handlers. Provided here for completeness.
type ManagerAddRemove interface {
	Manager
	AddHandler(ctx context.Context, handler Handler) error
	RemoveHandler(ctx context.Context, tag string) error
}
