package inbound

import "testing"

func TestValidateConfig(t *testing.T) {
	valid := &Config{Tag: "dns", Type: "dns", Listen: "127.0.0.1", Port: 1053, Network: "tcp,udp"}
	if err := ValidateConfig(valid); err != nil {
		t.Fatalf("valid DNS config: %v", err)
	}
	tests := []*Config{
		{Tag: "", Type: "dns", Port: 53},
		{Tag: "dns", Type: "dns", Port: 53, DNSGlobalQueryBurst: 1},
		{Tag: "redirect", Type: "redirect", Port: 12345, Network: "udp"},
		{Tag: "doh", Type: "doh", Port: 443, Network: "tcp"},
		{Tag: "udp", Type: "tproxy", Port: 12345, Network: "udp", UDPMaxSessions: -1},
	}
	for index, config := range tests {
		if err := ValidateConfig(config); err == nil {
			t.Fatalf("invalid config[%d] accepted", index)
		}
	}
}
