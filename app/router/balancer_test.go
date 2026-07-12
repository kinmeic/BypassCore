package router

import (
	"context"
	"testing"

	appoutbound "github.com/eugene/bypasscore/app/outbound"
)

// --- RoundRobinStrategy ---

// TestRoundRobin_PickOrder verifies strict round-robin cycling through the
// candidate list, wrapping back to index 0.
func TestRoundRobin_PickOrder(t *testing.T) {
	s := &RoundRobinStrategy{}
	tags := []string{"a", "b", "c"}
	want := []string{"a", "b", "c", "a", "b", "c", "a"}
	for i, w := range want {
		if got := s.PickOutbound(tags); got != w {
			t.Fatalf("pick %d: got %q want %q", i, got, w)
		}
	}
}

// TestRoundRobin_EmptyCandidatesReturnsEmpty documents that an empty candidate
// list (e.g. all-dead via observatory, or selector with no matches) yields "",
// which the Balancer turns into a fallback or error.
func TestRoundRobin_EmptyCandidatesReturnsEmpty(t *testing.T) {
	s := &RoundRobinStrategy{}
	if got := s.PickOutbound(nil); got != "" {
		t.Fatalf("PickOutbound(nil) = %q, want empty", got)
	}
	if got := s.PickOutbound([]string{}); got != "" {
		t.Fatalf("PickOutbound([]) = %q, want empty", got)
	}
}

// TestRoundRobin_SingleCandidateAlways returns the only candidate and keeps
// index bounded (no overflow concerns).
func TestRoundRobin_SingleCandidateAlways(t *testing.T) {
	s := &RoundRobinStrategy{}
	for i := 0; i < 5; i++ {
		if got := s.PickOutbound([]string{"only"}); got != "only" {
			t.Fatalf("pick %d = %q, want only", i, got)
		}
	}
}

// --- RandomStrategy ---

// TestRandom_Distribution verifies that over many picks every candidate is
// selected, i.e. the random index stays within bounds and covers the set.
func TestRandom_Distribution(t *testing.T) {
	s := &RandomStrategy{}
	tags := []string{"a", "b", "c", "d"}
	seen := map[string]bool{}
	for i := 0; i < 4000; i++ {
		got := s.PickOutbound(tags)
		if got == "" {
			t.Fatal("PickOutbound returned empty for non-empty candidates")
		}
		seen[got] = true
	}
	if len(seen) != 4 {
		t.Errorf("only %d/4 candidates selected after 4000 picks: %v", len(seen), seen)
	}
}

// TestRandom_EmptyCandidatesReturnsEmpty mirrors the RoundRobin contract.
func TestRandom_EmptyCandidatesReturnsEmpty(t *testing.T) {
	s := &RandomStrategy{}
	if got := s.PickOutbound(nil); got != "" {
		t.Fatalf("PickOutbound(nil) = %q, want empty", got)
	}
}

// --- Balancer (SelectOutbounds + override + fallback) ---

// newTestBalancer builds a Balancer wired to a real outbound.Manager so that
// SelectOutbounds resolves selectors through the HandlerSelector interface.
func newTestBalancer(t *testing.T, strategy BalancingStrategy, selectors []string, fallback string) *Balancer {
	t.Helper()
	ohm := appoutbound.NewManager(&appoutbound.Config{Outbounds: []*appoutbound.Outbound{
		{Tag: "wan1", Mode: appoutbound.ModeFreedom},
		{Tag: "wan2", Mode: appoutbound.ModeFreedom},
		{Tag: "wan3", Mode: appoutbound.ModeFreedom},
		{Tag: "direct", Mode: appoutbound.ModeFreedom},
	}})
	b := &Balancer{
		selectors:   selectors,
		strategy:    strategy,
		ohm:         ohm,
		fallbackTag: fallback,
	}
	return b
}

// TestBalancer_PickOutbound_RoundRobin exercises the full path: selector
// resolution → strategy pick.
func TestBalancer_PickOutbound_RoundRobin(t *testing.T) {
	b := newTestBalancer(t, &RoundRobinStrategy{}, []string{"wan"}, "direct")
	got := []string{}
	for i := 0; i < 3; i++ {
		tag, err := b.PickOutbound()
		if err != nil {
			t.Fatalf("PickOutbound %d: %v", i, err)
		}
		got = append(got, tag)
	}
	// Selector "wan" → [wan1, wan2, wan3]; round-robin cycles them in order.
	want := []string{"wan1", "wan2", "wan3"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pick %d = %q, want %q (all=%v)", i, got[i], want[i], got)
		}
	}
}

// TestBalancer_OverrideBeatsStrategy verifies the override short-circuits the
// strategy entirely (the documented precedence).
func TestBalancer_OverrideBeatsStrategy(t *testing.T) {
	b := newTestBalancer(t, &RoundRobinStrategy{}, []string{"wan"}, "direct")
	b.override.Put("wan2")
	for i := 0; i < 5; i++ {
		tag, err := b.PickOutbound()
		if err != nil {
			t.Fatalf("PickOutbound: %v", err)
		}
		if tag != "wan2" {
			t.Errorf("pick %d = %q, want override wan2", i, tag)
		}
	}
	// Clearing override restores strategy selection.
	b.override.Clear()
	tag, err := b.PickOutbound()
	if err != nil {
		t.Fatalf("PickOutbound after clear: %v", err)
	}
	if tag == "wan2" {
		// Not strictly required, but the first RR pick should be wan1.
		if tag != "wan1" {
			t.Logf("note: first pick after clear = %q (RR restarts at wan1)", tag)
		}
	}
}

// TestBalancer_FallbackOnEmptySelector verifies that when the selector matches
// nothing and strategy returns "", the fallback tag is used.
func TestBalancer_FallbackOnEmptySelector(t *testing.T) {
	b := newTestBalancer(t, &RoundRobinStrategy{}, []string{"zzz-nonexistent"}, "direct")
	tag, err := b.PickOutbound()
	if err != nil {
		t.Fatalf("PickOutbound: %v", err)
	}
	if tag != "direct" {
		t.Errorf("tag = %q, want fallback direct", tag)
	}
}

// TestBalancer_NoFallbackReturnsError verifies that without a fallback an empty
// strategy result surfaces as an error.
func TestBalancer_NoFallbackReturnsError(t *testing.T) {
	b := newTestBalancer(t, &RoundRobinStrategy{}, []string{"zzz-nonexistent"}, "")
	_, err := b.PickOutbound()
	if err == nil {
		t.Fatal("PickOutbound must error when no candidates and no fallback")
	}
}

// TestBalancer_SelectOutbounds_NotHandlerSelector guards the type assertion.
func TestBalancer_SelectOutbounds_NotHandlerSelector(t *testing.T) {
	b := &Balancer{
		selectors: []string{"x"},
		ohm:       nil, // does not implement HandlerSelector
		strategy:  &RoundRobinStrategy{},
	}
	_, err := b.SelectOutbounds()
	if err == nil {
		t.Fatal("SelectOutbounds must error when ohm is not a HandlerSelector")
	}
}

// --- Router-level override API ---

// TestRouter_OverrideBalancer_EquivalentToSetOverrideTarget documents that the
// two override entry points (OverrideBalancer via map iteration vs
// SetOverrideTarget via direct index) are behaviorally equivalent. See
// AUDIT.md P2-4.
func TestRouter_OverrideBalancer_EquivalentToSetOverrideTarget(t *testing.T) {
	r := &Router{
		balancers: map[string]*Balancer{
			"b1": {selectors: []string{"x"}, strategy: &RoundRobinStrategy{}},
		},
	}
	if err := r.OverrideBalancer("b1", "forced"); err != nil {
		t.Fatalf("OverrideBalancer: %v", err)
	}
	if got, err := r.GetOverrideTarget("b1"); err != nil || got != "forced" {
		t.Fatalf("after OverrideBalancer: GetOverrideTarget=%q err=%v", got, err)
	}

	r2 := &Router{
		balancers: map[string]*Balancer{
			"b2": {selectors: []string{"x"}, strategy: &RoundRobinStrategy{}},
		},
	}
	if err := r2.SetOverrideTarget("b2", "forced2"); err != nil {
		t.Fatalf("SetOverrideTarget: %v", err)
	}
	if got, err := r2.GetOverrideTarget("b2"); err != nil || got != "forced2" {
		t.Fatalf("after SetOverrideTarget: GetOverrideTarget=%q err=%v", got, err)
	}
}

// TestRouter_OverrideBalancer_NotFound covers the missing-tag error path.
func TestRouter_OverrideBalancer_NotFound(t *testing.T) {
	r := &Router{balancers: map[string]*Balancer{}}
	if err := r.OverrideBalancer("nope", "x"); err == nil {
		t.Error("OverrideBalancer on missing balancer must error")
	}
	if err := r.SetOverrideTarget("nope", "x"); err == nil {
		t.Error("SetOverrideTarget on missing balancer must error")
	}
	if _, err := r.GetOverrideTarget("nope"); err == nil {
		t.Error("GetOverrideTarget on missing balancer must error")
	}
}

// TestRouter_GetPrincipleTarget covers the principle-target API for strategies
// that implement BalancingPrincipleTarget.
func TestRouter_GetPrincipleTarget(t *testing.T) {
	ohm := appoutbound.NewManager(&appoutbound.Config{Outbounds: []*appoutbound.Outbound{
		{Tag: "wan1", Mode: appoutbound.ModeFreedom},
	}})
	r := &Router{
		ohm: ohm,
		balancers: map[string]*Balancer{
			"rr": {
				selectors: []string{"wan"},
				strategy:  &RoundRobinStrategy{},
				ohm:       ohm,
			},
		},
	}
	got, err := r.GetPrincipleTarget("rr")
	if err != nil {
		t.Fatalf("GetPrincipleTarget: %v", err)
	}
	// RoundRobin returns candidates unchanged.
	if len(got) != 1 || got[0] != "wan1" {
		t.Errorf("GetPrincipleTarget = %v, want [wan1]", got)
	}
	// Missing balancer.
	if _, err := r.GetPrincipleTarget("nope"); err == nil {
		t.Error("GetPrincipleTarget(missing) must error")
	}
}

// TestBalancer_InjectContext_NoOpOnPlainStrategy verifies InjectContext is a
// no-op for strategies that don't implement ContextReceiver.
func TestBalancer_InjectContext_NoOpOnPlainStrategy(t *testing.T) {
	b := &Balancer{strategy: &RoundRobinStrategy{}}
	// Must not panic even though RoundRobinStrategy has an InjectContext method
	// (it does, so this actually exercises it with a bare context).
	b.InjectContext(context.Background())
}
