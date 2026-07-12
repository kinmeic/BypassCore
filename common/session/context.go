package session

import (
	"context"

	c "github.com/eugene/bypasscore/common/ctx"
)

type sessionKey = c.SessionKey

const (
	inboundSessionKey  sessionKey = 1
	outboundSessionKey sessionKey = 2
	contentSessionKey  sessionKey = 3
)

// ContextWithInbound returns a new context with the given inbound.
func ContextWithInbound(ctx context.Context, inbound *Inbound) context.Context {
	return context.WithValue(ctx, inboundSessionKey, inbound)
}

// InboundFromContext returns the inbound in ctx, or nil.
func InboundFromContext(ctx context.Context) *Inbound {
	if inbound, ok := ctx.Value(inboundSessionKey).(*Inbound); ok {
		return inbound
	}
	return nil
}

// ContextWithOutbounds returns a new context with the given outbounds.
func ContextWithOutbounds(ctx context.Context, outbounds []*Outbound) context.Context {
	return context.WithValue(ctx, outboundSessionKey, outbounds)
}

// OutboundsFromContext returns the outbounds in ctx, or nil.
func OutboundsFromContext(ctx context.Context) []*Outbound {
	if outbounds, ok := ctx.Value(outboundSessionKey).([]*Outbound); ok {
		return outbounds
	}
	return nil
}

// ContextWithContent returns a new context with the given content.
func ContextWithContent(ctx context.Context, content *Content) context.Context {
	return context.WithValue(ctx, contentSessionKey, content)
}

// ContentFromContext returns the content in ctx, or nil.
func ContentFromContext(ctx context.Context) *Content {
	if content, ok := ctx.Value(contentSessionKey).(*Content); ok {
		return content
	}
	return nil
}

// GetForcedOutboundTagFromContext returns the forced outbound tag if set.
func GetForcedOutboundTagFromContext(ctx context.Context) string {
	if ContentFromContext(ctx) == nil {
		return ""
	}
	return ContentFromContext(ctx).Attribute("forcedOutboundTag")
}
