package inbound

import (
	"testing"
	"time"

	"github.com/eugene/bypasscore/transport"
)

func TestValidateConfig(t *testing.T) {
	valid := &Config{Tag: "dns", Type: "dns", Listen: "127.0.0.1", Port: 1053, Network: "tcp,udp"}
	if err := ValidateConfig(valid); err != nil {
		t.Fatalf("valid DNS config: %v", err)
	}
	if err := ValidateConfig(&Config{Tag: "caddy", Type: "socks", Port: 1081, Network: "tcp"}); err != nil {
		t.Fatalf("valid SOCKS5 config: %v", err)
	}
	if err := ValidateConfig(&Config{Tag: "caddy-alias", Type: "socks5", Port: 1082}); err != nil {
		t.Fatalf("valid SOCKS5 alias config: %v", err)
	}
	tests := []*Config{
		{Tag: "", Type: "dns", Port: 53},
		{Tag: "dns", Type: "dns", Port: 53, DNSGlobalQueryBurst: 1},
		{Tag: "redirect", Type: "redirect", Port: 12345, Network: "udp"},
		{Tag: "doh", Type: "doh", Port: 443, Network: "tcp"},
		{Tag: "udp", Type: "tproxy", Port: 12345, Network: "udp", UDPMaxSessions: -1},
		{Tag: "socks-udp", Type: "socks", Port: 1081, Network: "udp"},
		{Tag: "socks-sniff", Type: "socks", Port: 1081, Network: "tcp", Sniffing: true},
		{Tag: "socks-idle", Type: "socks", Port: 1081, Network: "tcp", TCPIdleTimeoutSeconds: 86401},
		{Tag: "tproxy-idle", Type: "tproxy", Port: 12345, Network: "tcp", TCPIdleTimeoutSeconds: 86401},
	}
	for index, config := range tests {
		if err := ValidateConfig(config); err == nil {
			t.Fatalf("invalid config[%d] accepted", index)
		}
	}
}

func TestTCPIdleTimeoutFromConfig(t *testing.T) {
	timeout, err := tcpIdleTimeoutFromConfig(&Config{Tag: "socks", Type: "socks", Port: 1081})
	if err != nil || timeout != transport.DefaultConnIdleTimeout {
		t.Fatalf("zero field: timeout=%v err=%v, want default %v", timeout, err, transport.DefaultConnIdleTimeout)
	}
	timeout, err = tcpIdleTimeoutFromConfig(&Config{Tag: "socks", Type: "socks", Port: 1081, TCPIdleTimeoutSeconds: -1})
	if err != nil || timeout != 0 {
		t.Fatalf("negative field: timeout=%v err=%v, want disabled", timeout, err)
	}
	timeout, err = tcpIdleTimeoutFromConfig(&Config{Tag: "socks", Type: "socks", Port: 1081, TCPIdleTimeoutSeconds: 60})
	if err != nil || timeout != time.Minute {
		t.Fatalf("60s field: timeout=%v err=%v, want 1m0s", timeout, err)
	}
	if _, err = tcpIdleTimeoutFromConfig(&Config{Tag: "socks", Type: "socks", Port: 1081, TCPIdleTimeoutSeconds: 86401}); err == nil {
		t.Fatal("out-of-range field accepted")
	}
}
