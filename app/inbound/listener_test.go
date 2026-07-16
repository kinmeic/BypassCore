package inbound

import (
	"testing"

	"github.com/eugene/bypasscore/app/dispatcher"
)

func TestParseInboundNetworks(t *testing.T) {
	for _, tc := range []struct {
		value    string
		tcp, udp bool
		valid    bool
	}{
		{"", true, false, true},
		{"tcp", true, false, true},
		{"udp", false, true, true},
		{"tcp, udp", true, true, true},
		{"notcp", false, false, false},
		{"tcp,quic", false, false, false},
	} {
		tcp, udp, err := parseInboundNetworks(tc.value)
		if (err == nil) != tc.valid || tcp != tc.tcp || udp != tc.udp {
			t.Errorf("parseInboundNetworks(%q) = %v,%v,%v", tc.value, tcp, udp, err)
		}
	}
}

func TestListenerLifecycleState(t *testing.T) {
	listener := New(nil, nil)
	if err := listener.Start(); err == nil {
		t.Fatal("nil listener configuration was accepted")
	}
	if listener.state != listenerNew {
		t.Fatalf("failed start state=%d, want new", listener.state)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := listener.Start(); err == nil {
		t.Fatal("closed listener restarted")
	}
}

func TestSameListenerBindingUsesEffectiveAddress(t *testing.T) {
	left := &Config{Type: "dns", Port: 53, Network: "tcp,udp"}
	right := &Config{Type: "DNS", Listen: "127.0.0.1", Port: 53, Network: "udp,tcp"}
	if !SameListenerBinding(left, right) {
		t.Fatal("equivalent DNS defaults were treated as a binding change")
	}
	left = &Config{Type: "tproxy", Listen: "[::1]", Port: 1234, Network: "tcp"}
	right = &Config{Type: "tproxy", Listen: "::1", Port: 1234, Network: "tcp"}
	if !SameListenerBinding(left, right) {
		t.Fatal("bracketed IPv6 address was treated as a binding change")
	}
}

func TestListenerReloadAdoptsNewConfig(t *testing.T) {
	initial := &Config{Tag: "old", Type: "redirect", Listen: "127.0.0.1", Port: 1234, Network: "tcp"}
	next := &Config{Tag: "new", Type: "redirect", Listen: "127.0.0.1", Port: 1234, Network: "tcp", Sniffing: true}
	listener := New(initial, dispatcher.New(nil, nil, nil))
	listener.state = listenerRunning
	if err := listener.Reload(next); err != nil {
		t.Fatal(err)
	}
	if listener.cfg != next || listener.inboundTag() != "new" {
		t.Fatal("listener retained its initial configuration after reload")
	}
}
