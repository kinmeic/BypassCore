package extension

import "context"

// ContextReceiver is for objects that need the parent context injected.
type ContextReceiver interface {
	InjectContext(ctx context.Context)
}
