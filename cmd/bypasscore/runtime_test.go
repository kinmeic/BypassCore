package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eugene/bypasscore/app/control"
	appinbound "github.com/eugene/bypasscore/app/inbound"
	appoutbound "github.com/eugene/bypasscore/app/outbound"
	bcnet "github.com/eugene/bypasscore/common/net"
	bcsession "github.com/eugene/bypasscore/common/session"
	featdns "github.com/eugene/bypasscore/features/dns"
	routingsession "github.com/eugene/bypasscore/features/routing/session"
	"github.com/eugene/bypasscore/infra/conf"
)

func TestRuntimeReloadDrainsLeasedConnection(t *testing.T) {
	registerDialerFactory()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	final := "direct"
	cfg := &Config{
		Outbounds: []*appoutbound.Outbound{{Tag: "direct", Mode: appoutbound.ModeFreedom}},
		Routing:   conf.RouterConfig{FinalOutboundTag: final},
	}
	service, err := newRuntimeService(context.Background(), "", cfg, "initial")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	target := bcnet.TCPDestination(bcnet.ParseAddress("127.0.0.1"), bcnet.Port(listener.Addr().(*net.TCPAddr).Port))
	routingContext := &routingsession.Context{Outbound: &bcsession.Outbound{Target: target}}
	conn, tag, _, _, err := service.DialRouted(context.Background(), routingContext, target)
	if err != nil {
		t.Fatal(err)
	}
	if tag != "direct" {
		t.Fatalf("tag=%q", tag)
	}
	serverConn := <-accepted
	defer serverConn.Close()
	old := service.current

	next := &Config{
		Outbounds: []*appoutbound.Outbound{{Tag: "direct", Mode: appoutbound.ModeFreedom}, {Tag: "block", Mode: appoutbound.ModeBlackhole}},
		Routing:   conf.RouterConfig{FinalOutboundTag: final},
	}
	raw, _ := json.Marshal(next)
	if _, err := service.Reload(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if !old.retired.Load() || old.refs.Load() != 1 {
		t.Fatalf("old snapshot was not retained: retired=%v refs=%d", old.retired.Load(), old.refs.Load())
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for old.refs.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if old.refs.Load() != 0 {
		t.Fatalf("old snapshot reference leaked: %d", old.refs.Load())
	}
}

func TestReloadCompatibilityAllowsMutableInboundOnly(t *testing.T) {
	current := &Config{Inbounds: []*appinbound.Config{{Tag: "dns", Type: "dns", Listen: "127.0.0.1", Port: 53, Network: "udp", MaxConcurrentQueries: 10}}}
	next := &Config{Inbounds: []*appinbound.Config{{Tag: "dns", Type: "dns", Listen: "127.0.0.1", Port: 53, Network: "udp", MaxConcurrentQueries: 20}}}
	if err := reloadCompatibility(current, next); err != nil {
		t.Fatalf("mutable change rejected: %v", err)
	}
	next.Inbounds[0].Port = 54
	if err := reloadCompatibility(current, next); err == nil {
		t.Fatal("port change did not require restart")
	}
}

func TestControlReloadDoesNotAdoptRequestContext(t *testing.T) {
	registerDialerFactory()
	initialRaw := []byte(`{"outbounds":[{"tag":"direct","mode":"freedom"}],"dns":{"servers":["localhost"],"hosts":{"alive.test":"192.0.2.9"}},"routing":{"finalOutboundTag":"direct"}}`)
	initial, hash, err := decodeConfig(initialRaw)
	if err != nil {
		t.Fatal(err)
	}
	service, err := newRuntimeService(context.Background(), "", initial, hash)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	nextRaw := []byte(`{"outbounds":[{"tag":"direct","mode":"freedom"}],"dns":{"servers":["localhost"],"hosts":{"alive.test":"192.0.2.9"},"disableCache":true},"routing":{"finalOutboundTag":"direct"}}`)
	requestCtx, cancel := context.WithCancel(context.Background())
	if _, err := service.Reload(requestCtx, nextRaw); err != nil {
		t.Fatal(err)
	}
	cancel()
	ips, _, err := service.LookupIPContext(context.Background(), "alive.test", featdns.IPOption{IPv4Enable: true})
	if err != nil {
		t.Fatalf("reloaded DNS inherited canceled request context: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "192.0.2.9" {
		t.Fatalf("unexpected DNS result: %v", ips)
	}
}

func TestLiveControlStatusAndReadiness(t *testing.T) {
	registerDialerFactory()
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()
	dir, err := os.MkdirTemp("/tmp", "bc-live-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "control.sock")
	cfg := &Config{
		Outbounds: []*appoutbound.Outbound{{Tag: "direct", Mode: appoutbound.ModeFreedom}},
		Routing:   conf.RouterConfig{FinalOutboundTag: "direct"},
		Inbounds:  []*appinbound.Config{{Tag: "dns", Type: "dns", Listen: "127.0.0.1", Port: port, Network: "udp"}},
	}
	service, err := newRuntimeService(context.Background(), "", cfg, "live-hash")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	controlServer, err := control.New(&control.Config{Enabled: true, Socket: socket}, service, capabilities())
	if err != nil {
		t.Fatal(err)
	}
	if err := controlServer.Start(); err != nil {
		t.Fatal(err)
	}
	defer controlServer.Close()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	client := &http.Client{Transport: transport, Timeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runDaemonWithReload(service, service, service, cfg.Inbounds, ctx, nil) }()
	deadline := time.Now().Add(time.Second)
	for !service.listeners.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	response, err := client.Get("http://unix/v1/status")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"ready":true`) || !strings.Contains(string(body), `"configHash":"live-hash"`) {
		cancel()
		t.Fatalf("unexpected status %d: %s", response.StatusCode, body)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDecodeConfigRejectsDuplicateKeys(t *testing.T) {
	_, _, err := decodeConfig([]byte(`{"outbounds":[],"routing":{},"routing":{"rules":[]}}`))
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate key accepted: %v", err)
	}
}
