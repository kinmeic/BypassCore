package router

import (
	"regexp"
	"testing"

	"github.com/eugene/bypasscore/common/geodata"
	bcnet "github.com/eugene/bypasscore/common/net"
)

// --- UserMatcher regexp boundary (AUDIT.md P1-3) ---

// TestUserMatcher_RegexpPrefix verifies the "regexp:" prefix is recognized via
// strings.CutPrefix: entries compile the suffix as a regexp. A bare "regexp:"
// (empty pattern) is dropped as meaningless rather than treated as a literal
// username (this was the fix for AUDIT.md P1-3, which previously used
// `len > 7` and kept "regexp:" as a literal).
func TestUserMatcher_RegexpPrefix(t *testing.T) {
	m := NewUserMatcher([]string{"regexp:^admin"})
	// "administrator" matches ^admin.
	if !m.Apply(&testContext{user: "administrator"}) {
		t.Error(`"administrator" should match regexp:^admin`)
	}
	if m.Apply(&testContext{user: "guest"}) {
		t.Error(`"guest" should not match regexp:^admin`)
	}

	// Bare "regexp:" (empty pattern) is now dropped, not a literal.
	m2 := NewUserMatcher([]string{"regexp:"})
	if m2.Apply(&testContext{user: "regexp:"}) {
		t.Error(`dropped empty-pattern "regexp:" should not match anything`)
	}
	if m2.Apply(&testContext{user: "anything"}) {
		t.Error(`dropped empty-pattern "regexp:" should not match anything`)
	}
}

// TestUserMatcher_InvalidRegexIgnored documents that a malformed regexp entry
// is silently dropped (not fatal).
func TestUserMatcher_InvalidRegexIgnored(t *testing.T) {
	m := NewUserMatcher([]string{"regexp:[", "alice"}) // "[" is invalid
	if !m.Apply(&testContext{user: "alice"}) {
		t.Error("valid literal 'alice' should still match after invalid regex dropped")
	}
	if m.Apply(&testContext{user: "["}) {
		t.Error("invalid regex should not match anything")
	}
}

// TestUserMatcher_LiteralAndRegexMix verifies both branches combine.
func TestUserMatcher_LiteralAndRegexMix(t *testing.T) {
	m := NewUserMatcher([]string{"alice", "regexp:^bob-"})
	if !m.Apply(&testContext{user: "alice"}) {
		t.Error("literal alice should match")
	}
	if !m.Apply(&testContext{user: "bob-42"}) {
		t.Error("regexp ^bob- should match bob-42")
	}
	if m.Apply(&testContext{user: "eve"}) {
		t.Error("eve should not match")
	}
}

// --- ProcessNameMatcher classification ---

// TestProcessNameMatcher_Classification verifies how the constructor splits
// names into bare process names, absolute paths, and folders, plus the "self/"
// special token. Note: ".exe" suffix is trimmed, so "curl" and "curl.exe" both
// become the bare name "curl" (no dedup is performed).
func TestProcessNameMatcher_Classification(t *testing.T) {
	m := NewProcessNameMatcher([]string{
		"curl",         // bare name
		"wget.exe",     // .exe stripped -> "wget"
		"/usr/bin/ssh", // abs path
		"/usr/bin/",    // folder
		"self/",        // match-self token
	})
	if !m.MatchSelf {
		t.Error("self/ should set MatchSelf")
	}
	if len(m.ProcessNames) != 2 || m.ProcessNames[0] != "curl" || m.ProcessNames[1] != "wget" {
		t.Errorf("ProcessNames = %v, want [curl wget]", m.ProcessNames)
	}
	if len(m.AbsPaths) != 1 || m.AbsPaths[0] != "/usr/bin/ssh" {
		t.Errorf("AbsPaths = %v, want [/usr/bin/ssh]", m.AbsPaths)
	}
	if len(m.Folders) != 1 || m.Folders[0] != "/usr/bin/" {
		t.Errorf("Folders = %v, want [/usr/bin/]", m.Folders)
	}
}

// TestProcessNameMatcher_Apply_NoSourceIPs returns false without invoking
// FindProcess (which would otherwise need a real connection).
func TestProcessNameMatcher_Apply_NoSourceIPs(t *testing.T) {
	m := NewProcessNameMatcher([]string{"curl"})
	if m.Apply(&testContext{}) { // no source IPs
		t.Error("Apply with no source IPs should return false without calling FindProcess")
	}
}

// --- AttributeMatcher ---

// TestAttributeMatcher_CaseInsensitiveKeys verifies header-style case folding.
func TestAttributeMatcher_CaseInsensitiveKeys(t *testing.T) {
	m := &AttributeMatcher{configuredKeys: map[string]*regexp.Regexp{
		"host": regexp.MustCompile(`^example\.com$`),
	}}
	// Config key is lowercase "host"; incoming "Host" should match.
	if !m.Match(map[string]string{"Host": "example.com"}) {
		t.Error(`"Host" header should match configured lowercase "host"`)
	}
	if m.Match(map[string]string{"Host": "other.com"}) {
		t.Error(`non-matching value should fail`)
	}
	// Missing key entirely.
	if m.Match(map[string]string{"X": "y"}) {
		t.Error("missing required attribute should fail")
	}
}

// TestAttributeMatcher_NilAttributesOnContext: Apply returns false when the
// context exposes no attributes (nil), not a panic.
func TestAttributeMatcher_NilAttributesOnContext(t *testing.T) {
	m := &AttributeMatcher{configuredKeys: map[string]*regexp.Regexp{
		"k": regexp.MustCompile(`v`),
	}}
	if m.Apply(&testContext{attributes: nil}) {
		t.Error("nil attributes should not match")
	}
}

// TestAttributeMatcher_MultipleKeysAllRequired: all configured keys must match.
func TestAttributeMatcher_MultipleKeysAllRequired(t *testing.T) {
	m := &AttributeMatcher{configuredKeys: map[string]*regexp.Regexp{
		"a": regexp.MustCompile(`1`),
		"b": regexp.MustCompile(`2`),
	}}
	if !m.Match(map[string]string{"a": "1", "b": "2"}) {
		t.Error("both matching should succeed")
	}
	if m.Match(map[string]string{"a": "1", "b": "x"}) {
		t.Error("one non-matching should fail")
	}
}

// --- DomainMatcher ---

// TestDomainMatcher_SubstrAndSubdomain covers domain: (substr + subdomain)
// matching and case-insensitivity.
func TestDomainMatcher_SubstrAndSubdomain(t *testing.T) {
	rules, err := geodata.ParseDomainRules([]string{"domain:google.com"}, geodata.Domain_Substr)
	if err != nil {
		t.Fatalf("ParseDomainRules: %v", err)
	}
	m, err := NewDomainMatcher(rules)
	if err != nil {
		t.Fatalf("NewDomainMatcher: %v", err)
	}
	cases := []struct {
		domain string
		want   bool
	}{
		{"google.com", true},
		{"www.google.com", true},
		{"docs.www.google.com", true},
		{"Google.COM", true}, // case-insensitive
		{"evilgoogle.com", false},
		{"google.com.evil.com", false},
		{"", false},
	}
	for _, c := range cases {
		ctx := &testContext{targetDomain: c.domain}
		if got := m.Apply(ctx); got != c.want {
			t.Errorf("domain %q: got %v want %v", c.domain, got, c.want)
		}
	}
}

// TestDomainMatcher_EmptyContextDomain: Apply returns false when context has
// no target domain (e.g. IP-only target).
func TestDomainMatcher_EmptyContextDomain(t *testing.T) {
	rules, _ := geodata.ParseDomainRules([]string{"domain:x.com"}, geodata.Domain_Substr)
	m, _ := NewDomainMatcher(rules)
	if m.Apply(&testContext{targetDomain: ""}) {
		t.Error("empty target domain should not match a domain rule")
	}
}

// --- IPMatcher ---

// TestIPMatcher_CIDRAndReverse covers CIDR matching and the !reverse prefix.
// Reverse semantics: a "!CIDR" rule matches IPs NOT in that CIDR. AnyMatch is
// OR across rules, so an IP matches if it's in a positive CIDR OR outside a
// reversed CIDR. This makes "!192.168.1.0/24" alone match essentially every IP
// except that /24.
func TestIPMatcher_CIDRAndReverse(t *testing.T) {
	// Positive-only: 10.0.0.0/8.
	rules, err := geodata.ParseIPRules([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseIPRules: %v", err)
	}
	m, err := NewIPMatcher(rules, MatcherAsType_Target)
	if err != nil {
		t.Fatalf("NewIPMatcher: %v", err)
	}
	ip := bcnet.ParseAddress
	cases := []struct {
		name string
		ips  []bcnet.IP
		want bool
	}{
		{"in-cidr", []bcnet.IP{ip("10.5.5.5").IP()}, true},
		{"unrelated", []bcnet.IP{ip("8.8.8.8").IP()}, false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		ctx := &testContext{targetIPs: c.ips}
		if got := m.Apply(ctx); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}

	// A bare reverse rule matches anything outside the reversed CIDR.
	revRules, err := geodata.ParseIPRules([]string{"!192.168.1.0/24"})
	if err != nil {
		t.Fatalf("ParseIPRules(reverse): %v", err)
	}
	rm, err := NewIPMatcher(revRules, MatcherAsType_Target)
	if err != nil {
		t.Fatalf("NewIPMatcher(reverse): %v", err)
	}
	if !rm.Apply(&testContext{targetIPs: []bcnet.IP{ip("8.8.8.8").IP()}}) {
		t.Error("8.8.8.8 (outside reversed 192.168.1.0/24) should match !192.168.1.0/24")
	}
	if rm.Apply(&testContext{targetIPs: []bcnet.IP{ip("192.168.1.5").IP()}}) {
		t.Error("192.168.1.5 (inside reversed CIDR) should NOT match !192.168.1.0/24")
	}
}

// TestIPMatcher_SourceType verifies the asType=Source path reads GetSourceIPs.
func TestIPMatcher_SourceType(t *testing.T) {
	rules, _ := geodata.ParseIPRules([]string{"10.0.0.0/8"})
	m, _ := NewIPMatcher(rules, MatcherAsType_Source)
	src := bcnet.ParseAddress("10.1.2.3").IP()
	if !m.Apply(&testContext{sourceIPs: []bcnet.IP{src}}) {
		t.Error("source IP in CIDR should match")
	}
	if m.Apply(&testContext{sourceIPs: []bcnet.IP{bcnet.ParseAddress("8.8.8.8").IP()}}) {
		t.Error("source IP outside CIDR should not match")
	}
}

// --- NetworkMatcher edge ---

// TestNetworkMatcher_Multiple covers a multi-network matcher.
func TestNetworkMatcher_Multiple(t *testing.T) {
	m := NewNetworkMatcher([]bcnet.Network{bcnet.Network_TCP, bcnet.Network_UDP})
	if !m.Apply(&testContext{network: bcnet.Network_TCP}) {
		t.Error("TCP should match [TCP,UDP]")
	}
	if !m.Apply(&testContext{network: bcnet.Network_UDP}) {
		t.Error("UDP should match [TCP,UDP]")
	}
	if m.Apply(&testContext{network: bcnet.Network_UNIX}) {
		t.Error("UNIX should not match [TCP,UDP]")
	}
}

// --- ProtocolMatcher prefix semantics ---

// TestProtocolMatcher_Prefix documents that protocol matching is a HasPrefix
// check, so "tls" matches "tls/1.3" but "ssh" does not match "tls".
func TestProtocolMatcher_Prefix(t *testing.T) {
	m := NewProtocolMatcher([]string{"tls", "http"})
	cases := []struct {
		proto string
		want  bool
	}{
		{"tls", true},
		{"tls/1.3", true},
		{"http/2", true},
		{"ssh", false},
		{"", false},
	}
	for _, c := range cases {
		if got := m.Apply(&testContext{protocol: c.proto}); got != c.want {
			t.Errorf("protocol %q: got %v want %v", c.proto, got, c.want)
		}
	}
}

// --- ConditionChan empty ---

// TestConditionChan_EmptyReturnsTrue: an empty ConditionChan (no conditions)
// vacuously applies — true. This is the "rule with fields that all matched"
// base case. (Note: BuildCondition rejects rules with zero fields, so an empty
// chan only arises from direct construction.)
func TestConditionChan_EmptyReturnsTrue(t *testing.T) {
	c := NewConditionChan()
	if !c.Apply(&testContext{}) {
		t.Error("empty ConditionChan should Apply true (vacuous)")
	}
}

// --- RoutingRule.BuildCondition ---

// TestBuildCondition_NoFieldsErrors verifies the guard against empty rules.
func TestBuildCondition_NoFieldsErrors(t *testing.T) {
	rr := &RoutingRule{TargetTag: &RoutingRule_Tag{Tag: "x"}}
	if _, err := rr.BuildCondition(); err == nil {
		t.Error("BuildCondition on a rule with no fields must error")
	}
}

// TestBuildCondition_PortList wires a port condition and checks it applies.
func TestBuildCondition_PortList(t *testing.T) {
	rr := &RoutingRule{
		TargetTag: &RoutingRule_Tag{Tag: "x"},
		PortList:  &bcnet.PortList{Range: []*bcnet.PortRange{{From: 443, To: 443}}},
	}
	cond, err := rr.BuildCondition()
	if err != nil {
		t.Fatalf("BuildCondition: %v", err)
	}
	if !cond.Apply(&testContext{targetPort: 443}) {
		t.Error("port 443 should match the 443-443 rule")
	}
	if cond.Apply(&testContext{targetPort: 80}) {
		t.Error("port 80 should not match the 443-443 rule")
	}
}
