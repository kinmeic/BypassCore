package router

import (
	"context"
	"testing"

	"github.com/eugene/bypasscore/common/geodata"
	bcnet "github.com/eugene/bypasscore/common/net"
)

// buildTestRouter constructs a router with simple rules (domain/IP/port) — no
// geodata files required — exercising the full PickRoute path.
func buildTestRouter(t *testing.T) *Router {
	domainRules, err := geodata.ParseDomainRules([]string{"domain:baidu.com", "domain:qq.com"}, geodata.Domain_Substr)
	if err != nil {
		t.Fatalf("ParseDomainRules: %v", err)
	}
	ipRules, err := geodata.ParseIPRules([]string{"192.168.0.0/16", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseIPRules: %v", err)
	}
	cfg := &Config{
		DomainStrategy: Config_AsIs,
		Rule: []*RoutingRule{
			{TargetTag: &RoutingRule_Tag{Tag: "wan1"}, Domain: domainRules},
			{TargetTag: &RoutingRule_Tag{Tag: "wan1"}, Ip: ipRules},
			{TargetTag: &RoutingRule_Tag{Tag: "proxy"}, PortList: &bcnet.PortList{Range: []*bcnet.PortRange{{From: 443, To: 443}}}},
		},
	}
	r := new(Router)
	if err := r.Init(context.Background(), cfg, nil, nil, nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return r
}

func TestPickRoute_DomainRule(t *testing.T) {
	r := buildTestRouter(t)
	route, err := r.PickRoute(&testContext{targetDomain: "www.baidu.com"})
	if err != nil {
		t.Fatalf("PickRoute: %v", err)
	}
	if got := route.GetOutboundTag(); got != "wan1" {
		t.Errorf("domain match: got %q want wan1", got)
	}
}

func TestPickRoute_IPCIDRRule(t *testing.T) {
	r := buildTestRouter(t)
	ip := bcnet.ParseAddress("192.168.1.5").IP()
	route, err := r.PickRoute(&testContext{targetIPs: []bcnet.IP{ip}})
	if err != nil {
		t.Fatalf("PickRoute: %v", err)
	}
	if got := route.GetOutboundTag(); got != "wan1" {
		t.Errorf("ip match: got %q want wan1", got)
	}
}

func TestPickRoute_PortRule(t *testing.T) {
	r := buildTestRouter(t)
	// 1.2.3.4:443 → not in CIDR rules, not a domain, but port 443 → proxy.
	ip := bcnet.ParseAddress("1.2.3.4").IP()
	route, err := r.PickRoute(&testContext{targetIPs: []bcnet.IP{ip}, targetPort: 443})
	if err != nil {
		t.Fatalf("PickRoute: %v", err)
	}
	if got := route.GetOutboundTag(); got != "proxy" {
		t.Errorf("port match: got %q want proxy", got)
	}
}

func TestPickRoute_NoMatch(t *testing.T) {
	r := buildTestRouter(t)
	// 8.8.8.8:53 → no rule matches → ErrNoClue.
	ip := bcnet.ParseAddress("8.8.8.8").IP()
	_, err := r.PickRoute(&testContext{targetIPs: []bcnet.IP{ip}, targetPort: 53, network: bcnet.Network_UDP})
	if err == nil {
		t.Fatal("expected no-match error, got nil")
	}
}

func TestPickRoute_DomainSubdomainMatch(t *testing.T) {
	// domain: rules match the domain itself and any subdomain.
	r := buildTestRouter(t)
	route, err := r.PickRoute(&testContext{targetDomain: "sub.www.baidu.com"})
	if err != nil {
		t.Fatalf("PickRoute subdomain: %v", err)
	}
	if got := route.GetOutboundTag(); got != "wan1" {
		t.Errorf("subdomain match: got %q want wan1", got)
	}
}
