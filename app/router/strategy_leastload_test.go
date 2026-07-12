package router

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/eugene/bypasscore/app/observatory"
)

// nodesFrom builds []*node helper for deterministic sort/selection tests.
func nodesFrom(specs ...struct {
	tag string
	rtt time.Duration // RTTDeviationCost (and Average when dev omitted)
}) []*node {
	out := make([]*node, 0, len(specs))
	for _, s := range specs {
		out = append(out, &node{
			Tag:              s.tag,
			RTTAverage:       s.rtt,
			RTTDeviation:     s.rtt,
			RTTDeviationCost: s.rtt,
		})
	}
	return out
}

// --- selectLeastLoad ---

// TestSelectLeastLoad_NoBaseline_ExpectedCount: with no baselines, the first
// `expected` nodes (sorted by cost) are returned.
func TestSelectLeastLoad_NoBaseline_ExpectedCount(t *testing.T) {
	s := &LeastLoadStrategy{settings: &StrategyLeastLoadConfig{Expected: 2}, ctx: context.Background()}
	nodes := nodesFrom(
		struct {
			tag string
			rtt time.Duration
		}{"c", 30 * time.Millisecond},
		struct {
			tag string
			rtt time.Duration
		}{"a", 10 * time.Millisecond},
		struct {
			tag string
			rtt time.Duration
		}{"b", 20 * time.Millisecond},
	)
	leastloadSort(nodes) // sorted: a, b, c
	got := s.selectLeastLoad(nodes)
	if len(got) != 2 || got[0].Tag != "a" || got[1].Tag != "b" {
		t.Errorf("selectLeastLoad(Expected=2, no baseline) = %v, want [a b]", tagsOf(got))
	}
}

// TestSelectLeastLoad_ExpectedExceedsAvailable returns all nodes when expected
// is larger than the candidate set.
func TestSelectLeastLoad_ExpectedExceedsAvailable(t *testing.T) {
	s := &LeastLoadStrategy{settings: &StrategyLeastLoadConfig{Expected: 10}, ctx: context.Background()}
	nodes := nodesFrom(struct {
		tag string
		rtt time.Duration
	}{"a", 10 * time.Millisecond})
	got := s.selectLeastLoad(nodes)
	if len(got) != 1 {
		t.Errorf("want all 1 node, got %d", len(got))
	}
}

// TestSelectLeastLoad_ExpectedZeroDefaultsToOne: Expected <= 0 means "select 1".
func TestSelectLeastLoad_ExpectedZeroDefaultsToOne(t *testing.T) {
	s := &LeastLoadStrategy{settings: &StrategyLeastLoadConfig{Expected: 0}, ctx: context.Background()}
	nodes := nodesFrom(
		struct {
			tag string
			rtt time.Duration
		}{"a", 10 * time.Millisecond},
		struct {
			tag string
			rtt time.Duration
		}{"b", 20 * time.Millisecond},
	)
	got := s.selectLeastLoad(nodes)
	if len(got) != 1 || got[0].Tag != "a" {
		t.Errorf("Expected=0 should default to 1 node: got %v", tagsOf(got))
	}
}

// TestSelectLeastLoad_BaselineFillUp documents the "bandwidth priority
// advanced" quirk (AUDIT.md P1-2): when Expected > nodes-under-baseline, the
// count is bumped up to Expected, pulling in nodes that exceed every baseline.
func TestSelectLeastLoad_BaselineFillUp(t *testing.T) {
	s := &LeastLoadStrategy{
		settings: &StrategyLeastLoadConfig{
			Expected:  3,
			Baselines: []int64{int64(100 * time.Millisecond), int64(200 * time.Millisecond)},
		},
		ctx: context.Background(),
	}
	// Sorted by cost already: only "a" (<100ms) and "b" (<200ms) are under a
	// baseline; "c" (250ms) exceeds both.
	nodes := nodesFrom(
		struct {
			tag string
			rtt time.Duration
		}{"a", 50 * time.Millisecond},
		struct {
			tag string
			rtt time.Duration
		}{"b", 150 * time.Millisecond},
		struct {
			tag string
			rtt time.Duration
		}{"c", 250 * time.Millisecond},
	)
	got := s.selectLeastLoad(nodes)
	if len(got) != 3 {
		t.Errorf("Expected=3 with fill-up should return 3 nodes, got %d (%v)", len(got), tagsOf(got))
	}
	if len(got) >= 3 && got[2].Tag != "c" {
		t.Errorf("third node = %q, want c (filled up despite exceeding baselines)", got[2].Tag)
	}
}

// TestSelectLeastLoad_BaselineSpeedPriority: Expected <= 0 with baselines is
// "speed priority" — select only nodes under some baseline, none if nothing
// qualifies. (Expected <= 0 is set to 1 internally only when baselines empty.)
func TestSelectLeastLoad_BaselineSpeedPriority(t *testing.T) {
	s := &LeastLoadStrategy{
		settings: &StrategyLeastLoadConfig{
			Expected:  0, // <= 0: speed priority
			Baselines: []int64{int64(100 * time.Millisecond)},
		},
		ctx: context.Background(),
	}
	// All nodes exceed 100ms baseline -> count stays 0; but Expected<=0 so the
	// final "count < expected" override (which requires Expected > 0) does NOT
	// fire, returning nodes[:0].
	nodes := nodesFrom(
		struct {
			tag string
			rtt time.Duration
		}{"a", 150 * time.Millisecond},
		struct {
			tag string
			rtt time.Duration
		}{"b", 200 * time.Millisecond},
	)
	got := s.selectLeastLoad(nodes)
	if len(got) != 0 {
		t.Errorf("speed priority with no qualifying nodes should return empty, got %v", tagsOf(got))
	}
}

// TestSelectLeastLoad_EmptyInput returns nil.
func TestSelectLeastLoad_EmptyInput(t *testing.T) {
	s := &LeastLoadStrategy{settings: &StrategyLeastLoadConfig{Expected: 1}, ctx: context.Background()}
	if got := s.selectLeastLoad(nil); got != nil {
		t.Errorf("selectLeastLoad(nil) = %v, want nil", got)
	}
}

func tagsOf(nodes []*node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Tag)
	}
	return out
}

// --- leastloadSort ---

// TestLeastloadSort_ByCost verifies the primary sort key (RTTDeviationCost)
// and the tie-breaker chain (Average, CountFail asc, CountAll desc, Tag).
func TestLeastloadSort_ByCost(t *testing.T) {
	nodes := []*node{
		{Tag: "z", RTTAverage: 50, RTTDeviation: 50, RTTDeviationCost: 30, CountAll: 10, CountFail: 1},
		{Tag: "a", RTTAverage: 10, RTTDeviation: 10, RTTDeviationCost: 10, CountAll: 10, CountFail: 1},
		{Tag: "m", RTTAverage: 20, RTTDeviation: 20, RTTDeviationCost: 20, CountAll: 10, CountFail: 1},
	}
	leastloadSort(nodes)
	got := tagsOf(nodes)
	want := []string{"a", "m", "z"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sort by cost: got %v want %v", got, want)
	}
}

// TestLeastloadSort_TieBreakers exercises the secondary keys when cost is equal.
func TestLeastloadSort_TieBreakers(t *testing.T) {
	// Same cost; lower Average wins.
	nodes := []*node{
		{Tag: "hi", RTTAverage: 50, RTTDeviationCost: 100, CountAll: 1, CountFail: 0},
		{Tag: "lo", RTTAverage: 10, RTTDeviationCost: 100, CountAll: 1, CountFail: 0},
	}
	leastloadSort(nodes)
	if nodes[0].Tag != "lo" {
		t.Errorf("average tie-break: first = %q, want lo", nodes[0].Tag)
	}

	// Same cost & average; fewer failures wins.
	nodes2 := []*node{
		{Tag: "bad", RTTAverage: 10, RTTDeviationCost: 100, CountAll: 5, CountFail: 4},
		{Tag: "good", RTTAverage: 10, RTTDeviationCost: 100, CountAll: 5, CountFail: 1},
	}
	leastloadSort(nodes2)
	if nodes2[0].Tag != "good" {
		t.Errorf("fail tie-break: first = %q, want good", nodes2[0].Tag)
	}

	// Same cost/average/fail; more total samples wins (CountAll desc).
	nodes3 := []*node{
		{Tag: "few", RTTAverage: 10, RTTDeviationCost: 100, CountAll: 5, CountFail: 1},
		{Tag: "many", RTTAverage: 10, RTTDeviationCost: 100, CountAll: 50, CountFail: 1},
	}
	leastloadSort(nodes3)
	if nodes3[0].Tag != "many" {
		t.Errorf("countall tie-break: first = %q, want many", nodes3[0].Tag)
	}

	// All equal; tag asc.
	nodes4 := []*node{
		{Tag: "zzz", RTTAverage: 10, RTTDeviationCost: 100, CountAll: 5, CountFail: 1},
		{Tag: "aaa", RTTAverage: 10, RTTDeviationCost: 100, CountAll: 5, CountFail: 1},
	}
	leastloadSort(nodes4)
	if nodes4[0].Tag != "aaa" {
		t.Errorf("tag tie-break: first = %q, want aaa", nodes4[0].Tag)
	}
}

// --- shouldSelectNode ---

func TestShouldSelectNode(t *testing.T) {
	s := &LeastLoadStrategy{settings: &StrategyLeastLoadConfig{MaxRTT: int64(200 * time.Millisecond), Tolerance: 0.5}, ctx: context.Background()}
	candidates := []string{"a", "b"}

	cases := []struct {
		name string
		v    *observatory.OutboundStatus
		want bool
	}{
		{"dead", &observatory.OutboundStatus{OutboundTag: "a", Alive: false}, false},
		{"not-candidate", &observatory.OutboundStatus{OutboundTag: "x", Alive: true, Delay: 10}, false},
		{"over-maxrtt", &observatory.OutboundStatus{OutboundTag: "a", Alive: true, Delay: 250}, false},
		{"ok", &observatory.OutboundStatus{OutboundTag: "a", Alive: true, Delay: 50}, true},
		{"tolerance-exceeded", &observatory.OutboundStatus{OutboundTag: "a", Alive: true, Delay: 50, HealthPing: &observatory.HealthPingMeasurementResult{All: 10, Fail: 9}}, false},
		{"tolerance-ok", &observatory.OutboundStatus{OutboundTag: "a", Alive: true, Delay: 50, HealthPing: &observatory.HealthPingMeasurementResult{All: 10, Fail: 2}}, true},
	}
	for _, c := range cases {
		if got := s.shouldSelectNode(c.v, candidates); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// --- getNodes (observer integration) ---

// TestLeastLoadStrategy_getNodes_NoObserver returns empty when observer is nil
// (instead of panicking).
func TestLeastLoadStrategy_getNodes_NoObserver(t *testing.T) {
	s := &LeastLoadStrategy{settings: &StrategyLeastLoadConfig{}, ctx: context.Background()}
	got := s.getNodes([]string{"a"})
	if len(got) != 0 {
		t.Errorf("getNodes with nil observer = %v, want empty", got)
	}
}

// TestLeastLoadStrategy_PickOutbound_NoCandidates returns "" (→ fallback).
func TestLeastLoadStrategy_PickOutbound_NoCandidates(t *testing.T) {
	s := NewLeastLoadStrategy(&StrategyLeastLoadConfig{})
	// No observer => getNodes empty => PickOutbound returns "".
	if got := s.PickOutbound([]string{"a"}); got != "" {
		t.Errorf("PickOutbound with no observer = %q, want empty", got)
	}
}
