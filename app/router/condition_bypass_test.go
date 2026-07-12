package router

import (
	"testing"

	bcnet "github.com/eugene/bypasscore/common/net"
)

// testContext is a minimal routing.Context for exercising conditions in
// isolation (no session/proxy deps).
type testContext struct {
	inboundTag   string
	sourceIPs    []bcnet.IP
	sourcePort   bcnet.Port
	targetIPs    []bcnet.IP
	targetPort   bcnet.Port
	targetDomain string
	network      bcnet.Network
	protocol     string
	user         string
	attributes   map[string]string
}

func (c *testContext) GetInboundTag() string             { return c.inboundTag }
func (c *testContext) GetSourceIPs() []bcnet.IP          { return c.sourceIPs }
func (c *testContext) GetSourcePort() bcnet.Port         { return c.sourcePort }
func (c *testContext) GetTargetIPs() []bcnet.IP          { return c.targetIPs }
func (c *testContext) GetTargetPort() bcnet.Port         { return c.targetPort }
func (c *testContext) GetLocalIPs() []bcnet.IP           { return nil }
func (c *testContext) GetLocalPort() bcnet.Port          { return 0 }
func (c *testContext) GetTargetDomain() string           { return c.targetDomain }
func (c *testContext) GetNetwork() bcnet.Network         { return c.network }
func (c *testContext) GetProtocol() string               { return c.protocol }
func (c *testContext) GetUser() string                   { return c.user }
func (c *testContext) GetVlessRoute() bcnet.Port         { return 0 }
func (c *testContext) GetAttributes() map[string]string  { return c.attributes }
func (c *testContext) GetSkipDNSResolve() bool           { return false }

func TestPortMatcher(t *testing.T) {
	pl := &bcnet.PortList{Range: []*bcnet.PortRange{
		{From: 80, To: 80},
		{From: 443, To: 450},
	}}
	m := NewPortMatcher(pl, MatcherAsType_Target)

	cases := []struct {
		port bcnet.Port
		want bool
	}{
		{80, true},
		{443, true},
		{447, true},
		{450, true},
		{451, false},
		{79, false},
		{0, false},
	}
	for _, c := range cases {
		ctx := &testContext{targetPort: c.port}
		if got := m.Apply(ctx); got != c.want {
			t.Errorf("port %d: got %v want %v", c.port, got, c.want)
		}
	}
}

func TestNetworkMatcher(t *testing.T) {
	m := NewNetworkMatcher([]bcnet.Network{bcnet.Network_TCP})
	if !m.Apply(&testContext{network: bcnet.Network_TCP}) {
		t.Error("TCP should match [TCP]")
	}
	if m.Apply(&testContext{network: bcnet.Network_UDP}) {
		t.Error("UDP should not match [TCP]")
	}
}

func TestProtocolMatcher(t *testing.T) {
	m := NewProtocolMatcher([]string{"http", "tls"})
	if !m.Apply(&testContext{protocol: "http/1.1"}) {
		t.Error(`"http/1.1" should match ["http","tls"]`)
	}
	if !m.Apply(&testContext{protocol: "tls"}) {
		t.Error(`"tls" should match`)
	}
	if m.Apply(&testContext{protocol: "ssh"}) {
		t.Error(`"ssh" should not match`)
	}
	if m.Apply(&testContext{protocol: ""}) {
		t.Error("empty protocol should not match")
	}
}

func TestUserMatcher(t *testing.T) {
	m := NewUserMatcher([]string{"alice", "bob"})
	if !m.Apply(&testContext{user: "alice"}) {
		t.Error("alice should match")
	}
	if m.Apply(&testContext{user: "eve"}) {
		t.Error("eve should not match")
	}
	if m.Apply(&testContext{user: ""}) {
		t.Error("empty user should not match")
	}
}

func TestInboundTagMatcher(t *testing.T) {
	m := NewInboundTagMatcher([]string{"inbound-a"})
	if !m.Apply(&testContext{inboundTag: "inbound-a"}) {
		t.Error("inbound-a should match")
	}
	if m.Apply(&testContext{inboundTag: "inbound-b"}) {
		t.Error("inbound-b should not match")
	}
}

func TestConditionChanAndAll(t *testing.T) {
	// ConditionChan requires all conditions to match (AND semantics).
	chan_ := NewConditionChan()
	chan_.Add(NewNetworkMatcher([]bcnet.Network{bcnet.Network_TCP}))
	chan_.Add(NewPortMatcher(&bcnet.PortList{Range: []*bcnet.PortRange{{From: 443, To: 443}}}, MatcherAsType_Target))

	if !chan_.Apply(&testContext{network: bcnet.Network_TCP, targetPort: 443}) {
		t.Error("TCP:443 should match both conditions")
	}
	if chan_.Apply(&testContext{network: bcnet.Network_UDP, targetPort: 443}) {
		t.Error("UDP:443 should fail the network condition")
	}
	if chan_.Apply(&testContext{network: bcnet.Network_TCP, targetPort: 80}) {
		t.Error("TCP:80 should fail the port condition")
	}
}
