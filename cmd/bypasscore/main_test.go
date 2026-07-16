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

func TestReloadRoutingConfigIsTransactional(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	initial := `{"outbounds":[{"tag":"direct","mode":"freedom"}],"routing":{"domainStrategy":"AsIs","rules":[]}}`
	if err := os.WriteFile(path, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	running, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ohm := appoutbound.NewManager(&appoutbound.Config{Outbounds: running.Outbounds})
	routerConfig, err := running.Routing.Build()
	if err != nil {
		t.Fatal(err)
	}
	r := new(router.Router)
	if err := r.Init(context.Background(), routerConfig, appdns.NewLocal(), ohm, nil); err != nil {
		t.Fatal(err)
	}

	updated := `{"outbounds":[{"tag":"direct","mode":"freedom"}],"routing":{"domainStrategy":"AsIs","rules":[{"ruleTag":"http","port":"80","outboundTag":"direct"}]}}`
	if err := os.WriteFile(path, []byte(updated), 0600); err != nil {
		t.Fatal(err)
	}
	if err := reloadRoutingConfig(path, running, r, ohm); err != nil {
		t.Fatalf("routing reload: %v", err)
	}
	if rules := r.ListRule(); len(rules) != 1 || rules[0].GetRuleTag() != "http" {
		t.Fatalf("reloaded rules=%v", rules)
	}

	immutableChange := `{"outbounds":[{"tag":"direct","mode":"freedom"},{"tag":"block","mode":"blackhole"}],"routing":{"domainStrategy":"AsIs","rules":[]}}`
	if err := os.WriteFile(path, []byte(immutableChange), 0600); err != nil {
		t.Fatal(err)
	}
	if err := reloadRoutingConfig(path, running, r, ohm); err == nil {
		t.Fatal("immutable runtime change was accepted")
	}
	if rules := r.ListRule(); len(rules) != 1 || rules[0].GetRuleTag() != "http" {
		t.Fatal("failed reload replaced the active rules")
	}
}
