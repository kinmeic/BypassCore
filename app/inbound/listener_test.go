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
