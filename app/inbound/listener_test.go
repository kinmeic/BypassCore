package inbound

import "testing"

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
