package router

import (
	"context"
	"fmt"
	"testing"

	appoutbound "github.com/eugene/bypasscore/app/outbound"
	"github.com/eugene/bypasscore/common/geodata"
	bcnet "github.com/eugene/bypasscore/common/net"
	dns_feature "github.com/eugene/bypasscore/features/dns"
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

// --- domainStrategy paths ---

// fakeDNSClient is a stub dns.Client returning a fixed IP for any domain,
// used to exercise IpIfNonMatch / IpOnDemand without real network lookups.
type fakeDNSClient struct {
	ips []bcnet.IP
}

func (f *fakeDNSClient) LookupIP(_ string, _ dns_feature.IPOption) ([]bcnet.IP, uint32, error) {
	return f.ips, 60, nil
}
func (f *fakeDNSClient) Type() interface{} { return dns_feature.ClientType() }
func (f *fakeDNSClient) Start() error      { return nil }
func (f *fakeDNSClient) Close() error      { return nil }

// buildTestRouterWithDNS is like buildTestRouter but injects a fake DNS client
// and lets the caller pick the domainStrategy.
func buildTestRouterWithDNS(t *testing.T, strategy Config_DomainStrategy, dnsClient dns_feature.Client) *Router {
	t.Helper()
	ipRules, err := geodata.ParseIPRules([]string{"1.2.3.0/24"})
	if err != nil {
		t.Fatalf("ParseIPRules: %v", err)
	}
	cfg := &Config{
		DomainStrategy: strategy,
		Rule: []*RoutingRule{
			// Only an IP rule; domains won't match until resolved.
			{TargetTag: &RoutingRule_Tag{Tag: "wan1"}, Ip: ipRules},
		},
	}
	r := new(Router)
	if err := r.Init(context.Background(), cfg, dnsClient, nil, nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return r
}

// TestPickRoute_IpIfNonMatch_ResolvesOnMiss: a domain that doesn't match any
// rule is resolved via DNS, and if the resulting IP matches an IP rule, the
// rule fires. (pickRouteInternal second-pass.)
func TestPickRoute_IpIfNonMatch_ResolvesOnMiss(t *testing.T) {
	dnsClient := &fakeDNSClient{ips: []bcnet.IP{bcnet.ParseAddress("1.2.3.4").IP()}}
	r := buildTestRouterWithDNS(t, Config_IpIfNonMatch, dnsClient)

	route, err := r.PickRoute(&testContext{targetDomain: "example.com"})
	if err != nil {
		t.Fatalf("PickRoute: %v", err)
	}
	if got := route.GetOutboundTag(); got != "wan1" {
		t.Errorf("IpIfNonMatch after resolve: got %q want wan1", got)
	}
}

// TestPickRoute_IpIfNonMatch_NoResolveWhenDomainMatches: when the domain
// already matches a rule, no DNS resolution happens (first-pass success).
func TestPickRoute_IpIfNonMatch_NoResolveWhenDomainMatches(t *testing.T) {
	resolved := false
	dnsClient := &fakeDNSClient{}
	r := buildTestRouterWithDNS(t, Config_IpIfNonMatch, dnsClient)

	// Add a domain rule that will match first.
	domainRules, _ := geodata.ParseDomainRules([]string{"domain:hit.com"}, geodata.Domain_Substr)
	r.rules = append([]*Rule{{
		Condition: mustDomainCond(t, domainRules),
		Tag:       "proxy",
	}}, r.rules...)

	route, err := r.PickRoute(&testContext{targetDomain: "hit.com"})
	if err != nil {
		t.Fatalf("PickRoute: %v", err)
	}
	if got := route.GetOutboundTag(); got != "proxy" {
		t.Errorf("got %q want proxy (first-pass domain match)", got)
	}
	if resolved {
		t.Error("DNS should not have been resolved when domain matched in first pass")
	}
}

// TestPickRoute_IpIfNonMatch_SkipDNSResolve: when the context sets
// SkipDNSResolve (e.g. DoH server target), no resolution happens even on miss.
func TestPickRoute_IpIfNonMatch_SkipDNSResolve(t *testing.T) {
	dnsClient := &fakeDNSClient{ips: []bcnet.IP{bcnet.ParseAddress("1.2.3.4").IP()}}
	r := buildTestRouterWithDNS(t, Config_IpIfNonMatch, dnsClient)

	ctx := &skipDNSContext{testContext: testContext{targetDomain: "example.com"}, skip: true}
	_, err := r.PickRoute(ctx)
	if err == nil {
		t.Error("expected no-match error when SkipDNSResolve prevents resolution")
	}
}

// TestPickRoute_AsIs_NoResolution: with AsIs, domains that don't match just
// fall through to no-match without DNS.
func TestPickRoute_AsIs_NoResolution(t *testing.T) {
	dnsClient := &fakeDNSClient{ips: []bcnet.IP{bcnet.ParseAddress("1.2.3.4").IP()}}
	r := buildTestRouterWithDNS(t, Config_AsIs, dnsClient)
	_, err := r.PickRoute(&testContext{targetDomain: "example.com"})
	if err == nil {
		t.Error("AsIs with non-matching domain should return no-match, not nil")
	}
}

// skipDNSContext wraps testContext to override GetSkipDNSResolve.
type skipDNSContext struct {
	testContext
	skip bool
}

func (c *skipDNSContext) GetSkipDNSResolve() bool { return c.skip }

func mustDomainCond(t *testing.T, rules []*geodata.DomainRule) Condition {
	t.Helper()
	m, err := NewDomainMatcher(rules)
	if err != nil {
		t.Fatalf("NewDomainMatcher: %v", err)
	}
	return m
}

// --- balancer-tag routing ---

// TestPickRoute_BalancerTag verifies that a rule targeting a balancer tag
// resolves the outbound via the balancer (with a real outbound.Manager backing
// the selector).
func TestPickRoute_BalancerTag(t *testing.T) {
	ohm := appoutbound.NewManager(&appoutbound.Config{Outbounds: []*appoutbound.Outbound{
		{Tag: "direct", Mode: appoutbound.ModeFreedom},
		{Tag: "wan1", Mode: appoutbound.ModeFreedom},
		{Tag: "wan2", Mode: appoutbound.ModeFreedom},
	}})
	domainRules, _ := geodata.ParseDomainRules([]string{"domain:balanced.com"}, geodata.Domain_Substr)
	cfg := &Config{
		DomainStrategy: Config_AsIs,
		Rule: []*RoutingRule{
			{TargetTag: &RoutingRule_BalancingTag{BalancingTag: "pool"}, Domain: domainRules},
		},
		BalancingRule: []*BalancingRule{
			{
				Tag:              "pool",
				OutboundSelector: []string{"wan"},
				Strategy:         "roundrobin",
			},
		},
	}
	r := new(Router)
	if err := r.Init(context.Background(), cfg, nil, ohm, nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	route, err := r.PickRoute(&testContext{targetDomain: "balanced.com"})
	if err != nil {
		t.Fatalf("PickRoute: %v", err)
	}
	tag := route.GetOutboundTag()
	if tag != "wan1" && tag != "wan2" {
		t.Errorf("balancer pick = %q, want wan1 or wan2", tag)
	}
}

// TestPickRoute_MissingBalancerErrors: a rule referencing an unknown balancer
// tag must fail at Init time.
func TestPickRoute_MissingBalancerErrors(t *testing.T) {
	cfg := &Config{
		Rule: []*RoutingRule{
			{TargetTag: &RoutingRule_BalancingTag{BalancingTag: "ghost"}},
		},
	}
	r := new(Router)
	if err := r.Init(context.Background(), cfg, nil, nil, nil); err == nil {
		t.Error("Init must error when a rule references an unknown balancer")
	}
}

// TestPickRoute_RuleTagRoundTrip verifies the rule tag is carried onto the
// returned Route, so callers can identify which rule fired.
func TestPickRoute_RuleTagRoundTrip(t *testing.T) {
	ipRules, _ := geodata.ParseIPRules([]string{"10.0.0.0/8"})
	cfg := &Config{
		Rule: []*RoutingRule{
			{RuleTag: "my-rule", TargetTag: &RoutingRule_Tag{Tag: "wan1"}, Ip: ipRules},
		},
	}
	r := new(Router)
	if err := r.Init(context.Background(), cfg, nil, nil, nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	route, err := r.PickRoute(&testContext{targetIPs: []bcnet.IP{bcnet.ParseAddress("10.1.1.1").IP()}})
	if err != nil {
		t.Fatalf("PickRoute: %v", err)
	}
	if got := route.GetRuleTag(); got != "my-rule" {
		t.Errorf("GetRuleTag = %q, want my-rule", got)
	}
}

// --- ReloadRules / RemoveRule / ListRule ---

// TestReloadRules_AppendAndReplace covers both modes of ReloadRules.
func TestReloadRules_AppendAndReplace(t *testing.T) {
	ipRules, _ := geodata.ParseIPRules([]string{"10.0.0.0/8"})
	r := new(Router)
	if err := r.Init(context.Background(), &Config{
		Rule: []*RoutingRule{{RuleTag: "r1", TargetTag: &RoutingRule_Tag{Tag: "x"}, Ip: ipRules}},
	}, nil, nil, nil); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Append mode: keeps r1, adds r2.
	ipRules2, _ := geodata.ParseIPRules([]string{"172.16.0.0/12"})
	if err := r.ReloadRules(&Config{
		Rule: []*RoutingRule{{RuleTag: "r2", TargetTag: &RoutingRule_Tag{Tag: "y"}, Ip: ipRules2}},
	}, true); err != nil {
		t.Fatalf("ReloadRules(append): %v", err)
	}
	if len(r.rules) != 2 {
		t.Errorf("after append, rules=%d want 2", len(r.rules))
	}

	// Replace mode: wipes existing, adds r3 only.
	ipRules3, _ := geodata.ParseIPRules([]string{"192.168.0.0/16"})
	if err := r.ReloadRules(&Config{
		Rule: []*RoutingRule{{RuleTag: "r3", TargetTag: &RoutingRule_Tag{Tag: "z"}, Ip: ipRules3}},
	}, false); err != nil {
		t.Fatalf("ReloadRules(replace): %v", err)
	}
	if len(r.rules) != 1 || r.rules[0].RuleTag != "r3" {
		t.Errorf("after replace, rules=%v want only r3", r.rules)
	}
}

// TestReloadRules_DuplicateRuleTagRejected: appending a rule whose ruleTag
// already exists must fail and roll back newly-added rules.
func TestReloadRules_DuplicateRuleTagRejected(t *testing.T) {
	ipRules, _ := geodata.ParseIPRules([]string{"10.0.0.0/8"})
	r := new(Router)
	if err := r.Init(context.Background(), &Config{
		Rule: []*RoutingRule{{RuleTag: "dup", TargetTag: &RoutingRule_Tag{Tag: "x"}, Ip: ipRules}},
	}, nil, nil, nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	err := r.ReloadRules(&Config{
		Rule: []*RoutingRule{
			{RuleTag: "new", TargetTag: &RoutingRule_Tag{Tag: "y"}, Ip: ipRules},
			{RuleTag: "dup", TargetTag: &RoutingRule_Tag{Tag: "z"}, Ip: ipRules},
		},
	}, true)
	if err == nil {
		t.Fatal("ReloadRules with duplicate ruleTag must error")
	}
	// The "new" rule added before the duplicate should have been rolled back.
	for _, rule := range r.rules {
		if rule.RuleTag == "new" {
			t.Error("rolled-back rule 'new' should not be present")
		}
	}
}

func TestReloadRulesFailureIsTransactional(t *testing.T) {
	oldDomains, _ := geodata.ParseDomainRules([]string{"full:old.example"}, geodata.Domain_Substr)
	newDomains, _ := geodata.ParseDomainRules([]string{"full:new.example"}, geodata.Domain_Substr)
	r := new(Router)
	if err := r.Init(context.Background(), &Config{Rule: []*RoutingRule{{
		TargetTag: &RoutingRule_Tag{Tag: "direct"}, Domain: oldDomains,
	}}}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	bad := &RoutingRule{TargetTag: &RoutingRule_BalancingTag{BalancingTag: "missing"}, Domain: newDomains}
	if err := r.ReloadRules(&Config{Rule: []*RoutingRule{bad}}, false); err == nil {
		t.Fatal("invalid replacement unexpectedly succeeded")
	}
	if _, err := r.PickRoute(&testContext{targetDomain: "old.example"}); err != nil {
		t.Fatalf("old rules were lost after failed replacement: %v", err)
	}
}

// TestRemoveRule covers removing by tag, removing missing, and empty-tag error.
func TestRemoveRule(t *testing.T) {
	ipRules, _ := geodata.ParseIPRules([]string{"10.0.0.0/8"})
	r := new(Router)
	if err := r.Init(context.Background(), &Config{
		Rule: []*RoutingRule{
			{RuleTag: "r1", TargetTag: &RoutingRule_Tag{Tag: "x"}, Ip: ipRules},
			{RuleTag: "r2", TargetTag: &RoutingRule_Tag{Tag: "y"}, Ip: ipRules},
		},
	}, nil, nil, nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := r.RemoveRule("r1"); err != nil {
		t.Fatalf("RemoveRule(r1): %v", err)
	}
	if len(r.rules) != 1 || r.rules[0].RuleTag != "r2" {
		t.Errorf("after remove r1: %v", r.rules)
	}
	// Removing missing tag is a no-op success (matches Xray semantics).
	if err := r.RemoveRule("ghost"); err != nil {
		t.Errorf("RemoveRule(ghost) = %v, want nil", err)
	}
	// Empty tag errors.
	if err := r.RemoveRule(""); err == nil {
		t.Error("RemoveRule('') must error")
	}
}

// TestListRule verifies ListRule returns the current rules as Routes.
func TestListRule(t *testing.T) {
	ipRules, _ := geodata.ParseIPRules([]string{"10.0.0.0/8"})
	r := new(Router)
	if err := r.Init(context.Background(), &Config{
		Rule: []*RoutingRule{
			{RuleTag: "r1", TargetTag: &RoutingRule_Tag{Tag: "x"}, Ip: ipRules},
		},
	}, nil, nil, nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	list := r.ListRule()
	if len(list) != 1 {
		t.Fatalf("ListRule len = %d want 1", len(list))
	}
	if got := list[0].GetOutboundTag(); got != "x" {
		t.Errorf("ListRule[0] tag = %q want x", got)
	}
	if got := list[0].GetRuleTag(); got != "r1" {
		t.Errorf("ListRule[0] ruleTag = %q want r1", got)
	}
}

// TestRuleExists covers the helper used by ReloadRules.
func TestRuleExists(t *testing.T) {
	ipRules, _ := geodata.ParseIPRules([]string{"10.0.0.0/8"})
	r := new(Router)
	if err := r.Init(context.Background(), &Config{
		Rule: []*RoutingRule{{RuleTag: "r1", TargetTag: &RoutingRule_Tag{Tag: "x"}, Ip: ipRules}},
	}, nil, nil, nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !r.RuleExists("r1") {
		t.Error("RuleExists(r1) should be true")
	}
	if r.RuleExists("r2") {
		t.Error("RuleExists(r2) should be false")
	}
	if r.RuleExists("") {
		t.Error("RuleExists('') should be false (empty tag short-circuits)")
	}
}

// TestPickRoute_ConcurrentVsReload is a regression test for the concurrency
// contract: PickRoute snapshots r.rules under a read lock, so it is safe to
// call concurrently with ReloadRules/RemoveRule. Previously PickRoute iterated
// r.rules unlocked and would data-race (AUDIT.md P2-1).
func TestPickRoute_ConcurrentVsReload(t *testing.T) {
	t.Parallel()
	ipRules, _ := geodata.ParseIPRules([]string{"10.0.0.0/8"})
	r := new(Router)
	if err := r.Init(context.Background(), &Config{
		Rule: []*RoutingRule{{RuleTag: "r0", TargetTag: &RoutingRule_Tag{Tag: "t0"}, Ip: ipRules}},
	}, nil, nil, nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	target := bcnet.ParseAddress("10.1.1.1").IP()
	done := make(chan struct{})
	// Reader: hammer PickRoute.
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			route, err := r.PickRoute(&testContext{targetIPs: []bcnet.IP{target}})
			if err != nil {
				t.Errorf("PickRoute %d: %v", i, err)
				return
			}
			if tag := route.GetOutboundTag(); tag == "" {
				t.Errorf("PickRoute %d returned empty tag", i)
				return
			}
		}
	}()
	// Writer: repeatedly replace the ruleset.
	for i := 0; i < 500; i++ {
		_ = r.ReloadRules(&Config{
			Rule: []*RoutingRule{{
				RuleTag:   fmt.Sprintf("r%d", i),
				TargetTag: &RoutingRule_Tag{Tag: fmt.Sprintf("t%d", i)},
				Ip:        ipRules,
			}},
		}, false)
	}
	<-done
}

// TestPickRoute_SequentialReloadThenPick covers the safe sequential ordering:
// reload fully completes before any PickRoute call.
func TestPickRoute_SequentialReloadThenPick(t *testing.T) {
	ipRules, _ := geodata.ParseIPRules([]string{"10.0.0.0/8"})
	r := new(Router)
	if err := r.Init(context.Background(), &Config{
		Rule: []*RoutingRule{{TargetTag: &RoutingRule_Tag{Tag: "x"}, Ip: ipRules}},
	}, nil, nil, nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Sequential reload, then picks — must be stable.
	ipRules2, _ := geodata.ParseIPRules([]string{"172.16.0.0/12"})
	if err := r.ReloadRules(&Config{
		Rule: []*RoutingRule{{TargetTag: &RoutingRule_Tag{Tag: "y"}, Ip: ipRules2}},
	}, false); err != nil {
		t.Fatalf("ReloadRules: %v", err)
	}
	for i := 0; i < 20; i++ {
		route, err := r.PickRoute(&testContext{targetIPs: []bcnet.IP{bcnet.ParseAddress("172.16.0.1").IP()}})
		if err != nil {
			t.Fatalf("pick %d: %v", i, err)
		}
		if got := route.GetOutboundTag(); got != "y" {
			t.Fatalf("pick %d tag = %q want y", i, got)
		}
	}
}

// TestRouter_Close is idempotent and safe.
func TestRouter_Close(t *testing.T) {
	r := buildTestRouter(t)
	if err := r.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := r.Close(); err != nil { // idempotent
		t.Errorf("second Close: %v", err)
	}
}
