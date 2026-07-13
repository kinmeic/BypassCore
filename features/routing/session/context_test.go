package session_test

import (
	"context"
	"testing"

	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/common/session"
	routingsession "github.com/eugene/bypasscore/features/routing/session"
)

// TestAsRoutingContext_NoOutbounds verifies that an empty outbounds slice
// does not panic (P3-4 regression: previously indexed out of range).
func TestAsRoutingContext_NoOutbounds(t *testing.T) {
	ctx := context.Background()
	// AsRoutingContext should not panic when there are no outbounds.
	rctx := routingsession.AsRoutingContext(ctx)
	if rctx == nil {
		t.Fatal("AsRoutingContext returned nil")
	}
	// GetTargetDomain on an empty context returns "".
	if got := rctx.GetTargetDomain(); got != "" {
		t.Errorf("GetTargetDomain = %q, want empty", got)
	}
}

// TestAsRoutingContext_WithOutbound verifies the normal path.
func TestAsRoutingContext_WithOutbound(t *testing.T) {
	dest := bcnet.TCPDestination(bcnet.ParseAddress("example.com"), bcnet.Port(443))
	ob := &session.Outbound{Target: dest}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})

	rctx := routingsession.AsRoutingContext(ctx)
	if rctx == nil {
		t.Fatal("AsRoutingContext returned nil")
	}
	if got := rctx.GetTargetDomain(); got != "example.com" {
		t.Errorf("GetTargetDomain = %q, want example.com", got)
	}
}

// TestContextWithOutbound_RoundTrip verifies setting and getting outbounds.
func TestContextWithOutbound_RoundTrip(t *testing.T) {
	dest := bcnet.TCPDestination(bcnet.ParseAddress("1.2.3.4"), bcnet.Port(80))
	ob := &session.Outbound{Target: dest}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})

	obs := session.OutboundsFromContext(ctx)
	if len(obs) != 1 {
		t.Fatalf("outbounds len = %d, want 1", len(obs))
	}
	if obs[0] != ob {
		t.Error("round-trip returned different outbound pointer")
	}
}
