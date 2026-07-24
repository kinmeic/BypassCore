package inbound

import (
	"errors"
	"testing"
)

func TestHealthClosedIsTerminalUntilRestart(t *testing.T) {
	health := newHealthTracker("dns")
	health.set("dns", "starting", nil, false)
	health.set("dns", "closed", nil, false)
	health.setComponent("dns", "udp", "failed", errors.New("late failure"), true)
	health.set("dns", "failed", errors.New("late failure"), true)
	if got := health.snapshot().State; got != "closed" {
		t.Fatalf("late callback changed closed health to %q", got)
	}
	health.set("dns", "starting", nil, false)
	health.setComponent("dns", "udp", "running", nil, false)
	if got := health.snapshot().State; got != "running" {
		t.Fatalf("restart health state = %q, want running", got)
	}
}
