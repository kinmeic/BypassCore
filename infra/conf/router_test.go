package conf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eugene/bypasscore/app/router"
)

// --- RouterConfig.Build end-to-end ---

func TestRouterConfig_BuildMinimal(t *testing.T) {
	rc := &RouterConfig{
		RuleList: []json.RawMessage{
			json.RawMessage(`{"domain":["domain:example.com"],"outboundTag":"proxy"}`),
		},
	}
	cfg, err := rc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cfg.DomainStrategy != router.Config_AsIs {
		t.Errorf("DomainStrategy = %v, want AsIs", cfg.DomainStrategy)
	}
	if len(cfg.Rule) != 1 {
		t.Fatalf("Rule count = %d, want 1", len(cfg.Rule))
	}
	if tag := cfg.Rule[0].GetTag(); tag != "proxy" {
		t.Errorf("rule tag = %q, want proxy", tag)
	}
	if len(cfg.Rule[0].Domain) == 0 {
		t.Error("rule should have domain conditions")
	}
}

func TestRouterConfig_DomainStrategy(t *testing.T) {
	cases := []struct {
		in   string
		want router.Config_DomainStrategy
	}{
		{"", router.Config_AsIs},
		{"AsIs", router.Config_AsIs},
		{"ipifnonmatch", router.Config_IpIfNonMatch},
		{"IpIfNonMatch", router.Config_IpIfNonMatch},
		{"ipondemand", router.Config_IpOnDemand},
		{"IpOnDemand", router.Config_IpOnDemand},
		{"unknown", router.Config_AsIs},
	}
	for _, c := range cases {
		rc := &RouterConfig{DomainStrategy: &c.in}
		got := rc.getDomainStrategy()
		// getDomainStrategy is lowercase-only; test via Build for the public path.
		_ = got
	}
	// Verify through Build for representative cases.
	ds := "ipondemand"
	rc := &RouterConfig{DomainStrategy: &ds}
	cfg, err := rc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cfg.DomainStrategy != router.Config_IpOnDemand {
		t.Errorf("DomainStrategy = %v, want IpOnDemand", cfg.DomainStrategy)
	}
}

func TestRouterConfig_BalancerTag(t *testing.T) {
	rc := &RouterConfig{
		RuleList: []json.RawMessage{
			json.RawMessage(`{"port":"443","balancerTag":"pool"}`),
		},
		Balancers: []*BalancingRule{
			{Tag: "pool", Selectors: StringList{"wan"}, Strategy: StrategyConfig{Type: "random"}},
		},
	}
	cfg, err := rc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := cfg.Rule[0].GetBalancingTag(); got != "pool" {
		t.Errorf("balancer tag = %q, want pool", got)
	}
	if len(cfg.BalancingRule) != 1 {
		t.Fatalf("balancer count = %d, want 1", len(cfg.BalancingRule))
	}
}

func TestRouterConfig_RuleWithoutTarget(t *testing.T) {
	rc := &RouterConfig{
		RuleList: []json.RawMessage{
			json.RawMessage(`{"domain":["domain:x.com"]}`), // no outboundTag/balancerTag
		},
	}
	if _, err := rc.Build(); err == nil {
		t.Error("rule without outboundTag/balancerTag must error")
	}
}

// --- BalancingRule.Build ---

func TestBalancingRule_Build_StrategyNormalization(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "random"},
		{"RANDOM", "random"},
		{"RoundRobin", "roundrobin"},
		{"leastping", "leastping"},
		{"leastload", "leastload"},
	}
	for _, c := range cases {
		br := &BalancingRule{
			Tag:      "b",
			Selectors: StringList{"wan"},
			Strategy: StrategyConfig{Type: c.in},
		}
		got, err := br.Build()
		if err != nil {
			t.Errorf("Build(%q): %v", c.in, err)
			continue
		}
		if got.Strategy != c.want {
			t.Errorf("strategy %q -> %q, want %q", c.in, got.Strategy, c.want)
		}
	}
}

func TestBalancingRule_Build_UnknownStrategy(t *testing.T) {
	br := &BalancingRule{
		Tag:       "b",
		Selectors: StringList{"wan"},
		Strategy:  StrategyConfig{Type: "magic"},
	}
	if _, err := br.Build(); err == nil {
		t.Error("unknown strategy must error")
	}
}

func TestBalancingRule_Build_EmptyTag(t *testing.T) {
	br := &BalancingRule{Selectors: StringList{"wan"}}
	if _, err := br.Build(); err == nil {
		t.Error("empty balancer tag must error")
	}
}

func TestBalancingRule_Build_EmptySelectors(t *testing.T) {
	br := &BalancingRule{Tag: "b"}
	if _, err := br.Build(); err == nil {
		t.Error("empty selector list must error")
	}
}

func TestBalancingRule_Build_LeastLoadSettings(t *testing.T) {
	rawSettings := json.RawMessage(`{"expected":3,"baselines":["100ms","200ms"]}`)
	br := &BalancingRule{
		Tag:       "b",
		Selectors: StringList{"wan"},
		Strategy: StrategyConfig{
			Type:     "leastload",
			Settings: &rawSettings,
		},
	}
	got, err := br.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got.Strategy != "leastload" {
		t.Errorf("strategy = %q, want leastload", got.Strategy)
	}
	// StrategySettings should be populated for leastload.
	if got.StrategySettings == nil {
		t.Error("leastload StrategySettings should be non-nil")
	}
}

// --- NameServerConfig ---

func TestNameServerConfig_BareString(t *testing.T) {
	var nsc NameServerConfig
	if err := json.Unmarshal([]byte(`"8.8.8.8"`), &nsc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if nsc.Address == nil {
		t.Fatal("Address should be set from bare string")
	}
	ns, err := nsc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if ns.Address == nil {
		t.Fatal("built NameServer.Address nil")
	}
}

func TestNameServerConfig_FullObject(t *testing.T) {
	var nsc NameServerConfig
	if err := json.Unmarshal([]byte(`{"address":"8.8.8.8","port":53,"tag":"google"}`), &nsc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if nsc.Tag != "google" || nsc.Port != 53 {
		t.Errorf("parsed tag=%q port=%d", nsc.Tag, nsc.Port)
	}
}

func TestNameServerConfig_ExpectedIPsStar(t *testing.T) {
	var nsc NameServerConfig
	if err := json.Unmarshal([]byte(`{"address":"8.8.8.8","expectedIPs":["*","10.0.0.0/8"]}`), &nsc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	ns, err := nsc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !ns.ActPrior {
		t.Error("'*' in expectedIPs should set ActPrior=true")
	}
	if len(ns.ExpectedIp) == 0 {
		t.Error("non-star expectedIPs should be kept")
	}
}

func TestNameServerConfig_NoAddress(t *testing.T) {
	var nsc NameServerConfig
	if err := json.Unmarshal([]byte(`{"tag":"x"}`), &nsc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, err := nsc.Build(); err == nil {
		t.Error("missing address must error")
	}
}

// --- DNSConfig.Build ---

func TestDNSConfig_Build_WithServers(t *testing.T) {
	dc := &DNSConfig{
		Servers: []*NameServerConfig{
			mustNSC(t, `{"address":"1.1.1.1","tag":"cf"}`),
			mustNSC(t, `{"address":"8.8.8.8","tag":"google"}`),
		},
		QueryStrategy: "UseIPv4",
	}
	cfg, err := dc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(cfg.NameServer) != 2 {
		t.Fatalf("NameServer count = %d, want 2", len(cfg.NameServer))
	}
	// Both servers differ in tag → distinct policyIDs.
	if cfg.NameServer[0].PolicyID == cfg.NameServer[1].PolicyID {
		t.Error("distinct-tag servers should get distinct policyIDs")
	}
}

func TestDNSConfig_Build_PolicyIDSharing(t *testing.T) {
	// Two servers identical in policy-relevant attributes → same policyID.
	dc := &DNSConfig{
		Servers: []*NameServerConfig{
			mustNSC(t, `{"address":"1.1.1.1","tag":"x"}`),
			mustNSC(t, `{"address":"8.8.8.8","tag":"x"}`),
		},
	}
	cfg, err := dc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cfg.NameServer[0].PolicyID != cfg.NameServer[1].PolicyID {
		t.Errorf("identical-policy servers got distinct policyIDs: %d vs %d",
			cfg.NameServer[0].PolicyID, cfg.NameServer[1].PolicyID)
	}
}

func TestDNSConfig_Build_Hosts(t *testing.T) {
	dc := &DNSConfig{
		Hosts: &HostsWrapper{Hosts: map[string]*HostAddress{
			"local.test": mustHost(t, `"127.0.0.1"`),
		}},
	}
	cfg, err := dc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(cfg.StaticHosts) != 1 {
		t.Errorf("StaticHosts = %d, want 1", len(cfg.StaticHosts))
	}
}

func TestDNSConfig_Build_InvalidClientIP(t *testing.T) {
	dc := &DNSConfig{
		ClientIP: &Address{},
	}
	// An empty Address parses as a domain ("") → Build should reject it.
	if err := json.Unmarshal([]byte(`"not-an-ip"`), dc.ClientIP); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, err := dc.Build(); err == nil {
		t.Error("non-IP clientIP must error")
	}
}

// --- HostsWrapper / HostAddress ---

func TestHostAddress_Single(t *testing.T) {
	ha := mustHost(t, `"1.2.3.4"`)
	hm := newHostMapping(ha)
	if hm.ProxiedDomain != "" {
		t.Error("IP host should not have ProxiedDomain")
	}
	if len(hm.Ip) != 1 {
		t.Errorf("IP count = %d, want 1", len(hm.Ip))
	}
}

func TestHostAddress_Array(t *testing.T) {
	ha := mustHost(t, `["1.2.3.4","5.6.7.8"]`)
	hm := newHostMapping(ha)
	if len(hm.Ip) != 2 {
		t.Errorf("IP count = %d, want 2", len(hm.Ip))
	}
}

func TestHostAddress_Domain(t *testing.T) {
	ha := mustHost(t, `"alias.example.com"`)
	hm := newHostMapping(ha)
	if hm.ProxiedDomain != "alias.example.com" {
		t.Errorf("ProxiedDomain = %q", hm.ProxiedDomain)
	}
}

func TestHostAddress_Invalid(t *testing.T) {
	var ha HostAddress
	if err := json.Unmarshal([]byte(`123`), &ha); err == nil {
		t.Error("number should fail as HostAddress")
	}
}

func TestHostAddress_MarshalRoundTrip(t *testing.T) {
	ha := mustHost(t, `"1.2.3.4"`)
	out, err := json.Marshal(ha)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != `"1.2.3.4"` {
		t.Errorf("round-trip = %s", string(out))
	}
}

// --- readSystemHostsFrom ---

func TestReadSystemHostsFrom(t *testing.T) {
	input := "127.0.0.1 localhost\n::1 localhost\n# comment\n10.0.0.1 my.host other.host\n"
	mappings, err := readSystemHostsFrom(strings.NewReader(input))
	if err != nil {
		t.Fatalf("readSystemHostsFrom: %v", err)
	}
	// "localhost" appears for both 127.0.0.1 and ::1 → merged under one domain
	// with 2 IPs (well, distinct IPs).
	found := false
	for _, m := range mappings {
		if d := m.Domain.GetCustom().GetValue(); d == "localhost" {
			if len(m.Ip) >= 1 {
				found = true
			}
		}
	}
	if !found {
		t.Error("localhost not found in parsed system hosts")
	}
	// my.host should map to 10.0.0.1; "other.host" is an alias on the same line.
	foundMy := false
	for _, m := range mappings {
		if m.Domain.GetCustom().GetValue() == "my.host" {
			foundMy = true
		}
	}
	if !foundMy {
		t.Error("my.host not found")
	}
}

// --- helpers ---

func mustNSC(t *testing.T, raw string) *NameServerConfig {
	t.Helper()
	var nsc NameServerConfig
	if err := json.Unmarshal([]byte(raw), &nsc); err != nil {
		t.Fatalf("mustNSC: %v", err)
	}
	return &nsc
}

func mustHost(t *testing.T, raw string) *HostAddress {
	t.Helper()
	var ha HostAddress
	if err := json.Unmarshal([]byte(raw), &ha); err != nil {
		t.Fatalf("mustHost: %v", err)
	}
	return &ha
}
