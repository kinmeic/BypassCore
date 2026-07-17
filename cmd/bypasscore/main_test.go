package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	appdns "github.com/eugene/bypasscore/app/dns"
	appinbound "github.com/eugene/bypasscore/app/inbound"
	appoutbound "github.com/eugene/bypasscore/app/outbound"
	"github.com/eugene/bypasscore/app/router"
)

func TestValidateRoutingTargetsRejectsUnknownOutbound(t *testing.T) {
	ohm := appoutbound.NewManager(&appoutbound.Config{Outbounds: []*appoutbound.Outbound{
		{Tag: "direct", Mode: appoutbound.ModeFreedom},
	}})
	cfg := &router.Config{Rule: []*router.RoutingRule{{
		TargetTag: &router.RoutingRule_Tag{Tag: "typo"},
	}}}
	if err := validateRoutingTargets(cfg, ohm); err == nil {
		t.Fatal("unknown routed outbound must fail closed")
	}
}

func TestValidateRoutingTargetsRejectsUnknownFinalOutbound(t *testing.T) {
	ohm := appoutbound.NewManager(&appoutbound.Config{Outbounds: []*appoutbound.Outbound{{Tag: "direct", Mode: appoutbound.ModeFreedom}}})
	if err := validateRoutingTargets(&router.Config{FinalOutboundTag: "typo"}, ohm); err == nil {
		t.Fatal("unknown final outbound must fail closed")
	}
}

func TestValidateRuntimeConfigRejectsUnknownDNSOutbound(t *testing.T) {
	cfg, _, err := decodeConfig([]byte(`{"outbounds":[{"tag":"direct","mode":"freedom"}],"dns":{"servers":[{"address":"tls://1.1.1.1:853","tag":"remote","outboundTag":"missing-outbound"}]},"routing":{"finalOutboundTag":"direct"}}`))
	if err != nil {
		t.Fatal(err)
	}
	manager := appoutbound.NewManager(&appoutbound.Config{Outbounds: cfg.Outbounds})
	defer manager.Close()
	if err := validateRuntimeConfigWithOutbounds(cfg, manager); err == nil {
		t.Fatal("unknown DNS outbound passed CLI-equivalent validation")
	}
}

func TestRunDaemonDNSContextShutdownReleasesPort(t *testing.T) {
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = runDaemon(nil, nil, appdns.NewLocal(), []*appinbound.Config{{
		Tag: "dns-test", Type: "dns", Listen: "127.0.0.1", Port: port, Network: "udp",
	}}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	rebound, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatalf("DNS port was not released: %v", err)
	}
	_ = rebound.Close()
}

func TestRunDaemonCleansStartedDNSOnLaterConfigError(t *testing.T) {
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	err = runDaemon(nil, nil, appdns.NewLocal(), []*appinbound.Config{{
		Tag: "dns-test", Type: "dns", Listen: "127.0.0.1", Port: port, Network: "udp",
	}, nil}, context.Background())
	if err == nil {
		t.Fatal("nil inbound configuration was accepted")
	}
	rebound, bindErr := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if bindErr != nil {
		t.Fatalf("DNS port leaked after startup error: %v", bindErr)
	}
	_ = rebound.Close()
}

func TestLoadConfigRejectsUnknownTopLevelField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"outbounds":[],"routng":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("unknown top-level field must be rejected")
	}
}
