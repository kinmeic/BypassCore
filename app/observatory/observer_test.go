package observatory

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appoutbound "github.com/eugene/bypasscore/app/outbound"
)

// TestObserver_SerialModeProbesAllInOneRound is the regression test for the
// AUDIT.md P5-1 fix: in serial mode, the background loop used to sleep
// `probeInterval` *between each probe*, so a full round of N outbounds took
// N×interval. The fix sleeps once per round (between rounds), matching the
// concurrent branch. This test stands up a fast 204 probe server, starts the
// observer with a 3-outbound selector and a short interval, and asserts that
// all three outbounds appear probed within a window that would be impossible
// under the old N×interval cadence.
func TestObserver_SerialModeProbesAllInOneRound(t *testing.T) {
	// Probe server returns 204 immediately.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ohm := appoutbound.NewManager(&appoutbound.Config{Outbounds: []*appoutbound.Outbound{
		{Tag: "a", Mode: appoutbound.ModeFreedom},
		{Tag: "b", Mode: appoutbound.ModeFreedom},
		{Tag: "c", Mode: appoutbound.ModeFreedom},
	}})

	// interval = 5s. Old behavior: 3 outbounds × 5s = 15s for one round.
	// New behavior: round completes in ~probe-time, then 5s sleep. Assert all
	// three are alive well before 15s.
	cfg := &Config{
		SubjectSelector:   []string{"a", "b", "c"},
		ProbeUrl:          srv.URL,
		ProbeInterval:     int64(5 * time.Second),
		EnableConcurrency: false, // serial mode
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o, err := New(ctx, cfg, ohm)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := o.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer o.Close()

	// Wait up to 6s for all three outbounds to be reported alive. Under the
	// old serial cadence (15s for 3×5s), this would time out.
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		result, _ := o.GetObservation(ctx)
		obs := result.(*ObservationResult)
		if countAlive(obs) == 3 {
			return // pass: full round completed within one interval
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("serial mode did not probe all 3 outbounds within one interval (old N×interval bug); alive=%d",
		countAlive(o.snapshot()))
}

// TestObserver_ConcurrentModeProbesAll mirrors the serial test for the
// concurrent branch (which already had correct round cadence).
func TestObserver_ConcurrentModeProbesAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ohm := appoutbound.NewManager(&appoutbound.Config{Outbounds: []*appoutbound.Outbound{
		{Tag: "a", Mode: appoutbound.ModeFreedom},
		{Tag: "b", Mode: appoutbound.ModeFreedom},
	}})
	cfg := &Config{
		SubjectSelector:   []string{"a", "b"},
		ProbeUrl:          srv.URL,
		ProbeInterval:     int64(5 * time.Second),
		EnableConcurrency: true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o, err := New(ctx, cfg, ohm)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := o.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer o.Close()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		result, _ := o.GetObservation(ctx)
		obs := result.(*ObservationResult)
		if countAlive(obs) == 2 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("concurrent mode did not probe both outbounds in time")
}

func countAlive(obs *ObservationResult) int {
	n := 0
	for _, s := range obs.Status {
		if s.Alive {
			n++
		}
	}
	return n
}

// snapshot returns the current status without going through the proto return.
func (o *Observer) snapshot() *ObservationResult {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	out := make([]*OutboundStatus, len(o.status))
	copy(out, o.status)
	return &ObservationResult{Status: out}
}

// TestNew_RequiresOutboundManager guards the constructor nil check.
func TestNew_RequiresOutboundManager(t *testing.T) {
	if _, err := New(context.Background(), &Config{SubjectSelector: []string{"x"}}, nil); err == nil {
		t.Error("New with nil ohm must error")
	}
}

// TestNew_NoSelectorStartIsNoOp verifies Start returns nil without launching
// a loop when there is nothing to probe.
func TestObserver_StartNoSelector(t *testing.T) {
	ohm := appoutbound.NewManager(nil)
	o, err := New(context.Background(), &Config{}, ohm)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := o.Start(); err != nil {
		t.Errorf("Start with no selector: %v", err)
	}
	if err := o.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestApplyBinding covers the portable LocalIP subset of binding.
func TestApplyBinding(t *testing.T) {
	// applyBinding mutates a *net.Dialer; verify it sets LocalAddr for a valid
	// IP and skips for empty/invalid.
	dialer := &net.Dialer{}
	applyBinding(dialer, &appoutbound.BindConfig{LocalIP: "127.0.0.1"})
	if dialer.LocalAddr == nil {
		t.Error("LocalAddr should be set for valid LocalIP")
	}

	dialer2 := &net.Dialer{}
	applyBinding(dialer2, &appoutbound.BindConfig{LocalIP: "not-an-ip"})
	if dialer2.LocalAddr != nil {
		t.Error("LocalAddr should remain nil for invalid LocalIP")
	}

	dialer3 := &net.Dialer{}
	applyBinding(dialer3, &appoutbound.BindConfig{LocalIP: ""})
	if dialer3.LocalAddr != nil {
		t.Error("LocalAddr should remain nil for empty LocalIP")
	}

	applyBinding(dialer3, nil) // no panic
}
