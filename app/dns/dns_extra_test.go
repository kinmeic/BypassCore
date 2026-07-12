package dns

import (
	"errors"
	"testing"
	"time"

	"github.com/eugene/bypasscore/common/geodata"
	bcnet "github.com/eugene/bypasscore/common/net"
	dns_feature "github.com/eugene/bypasscore/features/dns"
)

// ipOf parses a literal IP into bcnet.IP.
func ipOf(s string) bcnet.IP { return bcnet.ParseAddress(s).IP() }

// --- StaticHosts (extended) ---

// TestStaticHosts_MultipleIPs verifies a host mapping with several IPs returns
// all of them, filtered by the IP option.
func TestStaticHosts_MultipleIPs(t *testing.T) {
	cfg := &Config{
		StaticHosts: []*Config_HostMapping{
			{
				Domain: mustDomainRule(t, "multi.test"),
				Ip:     [][]byte{{1, 2, 3, 4}, {5, 6, 7, 8}},
			},
		},
	}
	hosts, err := NewStaticHosts(cfg.StaticHosts)
	if err != nil {
		t.Fatalf("NewStaticHosts: %v", err)
	}
	addrs, err := hosts.Lookup("multi.test", dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("want 2 addrs, got %d", len(addrs))
	}
}

// TestStaticHosts_AliasDepthLimit documents the maxDepth=5 recursion cap on
// alias chains. A chain longer than 5 returns the last alias (a domain, not an
// IP) rather than erroring or looping forever.
func TestStaticHosts_AliasDepthLimit(t *testing.T) {
	// Build a -> b -> c -> ... -> g -> 127.0.0.1  (7 hops, exceeds depth 5).
	mappings := []*Config_HostMapping{}
	chain := []string{"a", "b", "c", "d", "e", "f", "g"}
	for i := 0; i < len(chain)-1; i++ {
		mappings = append(mappings, &Config_HostMapping{
			Domain:         mustDomainRule(t, chain[i]+".test"),
			ProxiedDomain: chain[i+1] + ".test",
		})
	}
	mappings = append(mappings, &Config_HostMapping{
		Domain: mustDomainRule(t, "g.test"),
		Ip:     [][]byte{{127, 0, 0, 1}},
	})
	hosts, err := NewStaticHosts(mappings)
	if err != nil {
		t.Fatalf("NewStaticHosts: %v", err)
	}
	// Lookup must terminate (no infinite recursion); result may be a partial
	// unwrap but the call must not hang or panic.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = hosts.Lookup("a.test", dns_feature.IPOption{IPv4Enable: true})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Lookup on deep alias chain hung (possible infinite recursion)")
	}
}

// TestStaticHosts_RCode verifies the "#<code>" proxied-domain form produces an
// RCode error for nonzero codes and ErrEmptyResponse for code 0.
func TestStaticHosts_RCode(t *testing.T) {
	cfg := &Config{
		StaticHosts: []*Config_HostMapping{
			{Domain: mustDomainRule(t, "refused.test"), ProxiedDomain: "#5"}, // REFUSED
			{Domain: mustDomainRule(t, "empty.test"), ProxiedDomain: "#0"},
		},
	}
	hosts, err := NewStaticHosts(cfg.StaticHosts)
	if err != nil {
		t.Fatalf("NewStaticHosts: %v", err)
	}
	_, err = hosts.Lookup("refused.test", dns_feature.IPOption{IPv4Enable: true})
	if err == nil {
		t.Fatal("refused.test should return RCode error")
	}
	if rcode := dns_feature.RCodeFromError(err); rcode != 5 {
		t.Errorf("rcode = %d, want 5", rcode)
	}
	_, err = hosts.Lookup("empty.test", dns_feature.IPOption{IPv4Enable: true})
	if !errors.Is(err, dns_feature.ErrEmptyResponse) {
		t.Errorf("empty.test err = %v, want ErrEmptyResponse", err)
	}
}

// TestStaticHosts_InvalidRCode verifies malformed rcode strings are rejected
// at construction time.
func TestStaticHosts_InvalidRCode(t *testing.T) {
	cfg := &Config{
		StaticHosts: []*Config_HostMapping{
			{Domain: mustDomainRule(t, "bad.test"), ProxiedDomain: "#not-a-number"},
		},
	}
	if _, err := NewStaticHosts(cfg.StaticHosts); err == nil {
		t.Fatal("NewStaticHosts must reject non-numeric rcode")
	}
}

// TestStaticHosts_EmptyConfig: a nil/empty hosts config yields a working but
// always-nil Lookup.
func TestStaticHosts_EmptyConfig(t *testing.T) {
	hosts, err := NewStaticHosts(nil)
	if err != nil {
		t.Fatalf("NewStaticHosts(nil): %v", err)
	}
	addrs, err := hosts.Lookup("anything.test", dns_feature.IPOption{IPv4Enable: true})
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if addrs != nil {
		t.Errorf("addrs = %v, want nil", addrs)
	}
}

// TestStaticHosts_IPv6Filtering: with only IPv6 enabled, IPv4 records are
// filtered out → returns empty (len 0) slice, not nil, indicating "recorded
// but no match".
func TestStaticHosts_IPv6Filtering(t *testing.T) {
	cfg := &Config{
		StaticHosts: []*Config_HostMapping{
			{Domain: mustDomainRule(t, "v4only.test"), Ip: [][]byte{{1, 2, 3, 4}}},
		},
	}
	hosts, _ := NewStaticHosts(cfg.StaticHosts)
	addrs, _ := hosts.Lookup("v4only.test", dns_feature.IPOption{IPv6Enable: true})
	if addrs != nil && len(addrs) != 0 {
		t.Errorf("v4-only host with IPv6 option = %v, want empty", addrs)
	}
}

// --- merge (record combining) ---

// rec builds an *IPRecord that expires in the future with the given IPs.
func rec(ips ...bcnet.IP) *IPRecord {
	return &IPRecord{IP: ips, Expire: time.Now().Add(60 * time.Second)}
}

func TestMerge_IPv4Only(t *testing.T) {
	opt := dns_feature.IPOption{IPv4Enable: true}
	ips, _, err := merge(opt, rec(ipOf("1.2.3.4")), nil)
	if err != nil {
		t.Fatalf("merge v4: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(ipOf("1.2.3.4")) {
		t.Errorf("merge v4 ips = %v, want [1.2.3.4]", ips)
	}
}

func TestMerge_BothFamilies(t *testing.T) {
	opt := dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true}
	v6 := ipOf("::1")
	ips, _, err := merge(opt, rec(ipOf("1.2.3.4")), rec(v6))
	if err != nil {
		t.Fatalf("merge both: %v", err)
	}
	if len(ips) != 2 {
		t.Errorf("want 2 ips (v4+v6), got %d", len(ips))
	}
}

func TestMerge_NilRecordsReturnsNotFound(t *testing.T) {
	opt := dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true}
	_, _, err := merge(opt, nil, nil)
	if err == nil {
		t.Error("merge of nil records should error")
	}
}

func TestMerge_OneFamilyEmpty(t *testing.T) {
	// Asking both families; v4 returns IPs, v6 record is nil (errRecordNotFound).
	// Documented behavior of merge: a nil v6 record short-circuits to
	// errRecordNotFound because getIPs on a nil *IPRecord returns that sentinel
	// and merge's "Is(err, errRecordNotFound)" branch fires.
	opt := dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true}
	_, _, err := merge(opt, rec(ipOf("1.2.3.4")), nil)
	if !errors.Is(err, errRecordNotFound) {
		t.Errorf("merge with nil v6 record err = %v, want errRecordNotFound", err)
	}
}

// --- makeGroups (parallel-query grouping) ---

// TestMakeGroups_AdjacentPolicyID verifies that only *adjacent* clients with
// the same policyID are merged into one group.
func TestMakeGroups_AdjacentPolicyID(t *testing.T) {
	// policyIDs: 1 1 2 2 2 1  → groups [0-1],[2-4],[5]
	clients := []*Client{
		{policyID: 1}, {policyID: 1},
		{policyID: 2}, {policyID: 2}, {policyID: 2},
		{policyID: 1},
	}
	groups, groupOf := makeGroups(clients)
	if len(groups) != 3 {
		t.Fatalf("want 3 groups, got %d: %v", len(groups), groups)
	}
	// Group boundaries.
	want := []group{{0, 1}, {2, 4}, {5, 5}}
	for i, g := range groups {
		if g != want[i] {
			t.Errorf("group[%d] = %v, want %v", i, g, want[i])
		}
	}
	// Each client maps to its group index.
	wantGroupOf := []int{0, 0, 1, 1, 1, 2}
	for i, g := range groupOf {
		if g != wantGroupOf[i] {
			t.Errorf("groupOf[%d] = %d, want %d", i, g, wantGroupOf[i])
		}
	}
}

func TestMakeGroups_SingleClient(t *testing.T) {
	groups, groupOf := makeGroups([]*Client{{policyID: 1}})
	if len(groups) != 1 || groups[0] != (group{0, 0}) {
		t.Errorf("single client groups = %v, want [{0 0}]", groups)
	}
	if len(groupOf) != 1 || groupOf[0] != 0 {
		t.Errorf("single client groupOf = %v, want [0]", groupOf)
	}
}

func TestMakeGroups_Empty(t *testing.T) {
	groups, groupOf := makeGroups(nil)
	if groups != nil || groupOf != nil {
		t.Errorf("empty makeGroups = %v/%v, want nil/nil", groups, groupOf)
	}
}

// --- mergeQueryErrors ---

func TestMergeQueryErrors_AllRecordNotFound(t *testing.T) {
	// All errRecordNotFound → result is errRecordNotFound (no server responded).
	err := mergeQueryErrors("x.test", []error{errRecordNotFound, errRecordNotFound})
	if !errors.Is(err, errRecordNotFound) {
		t.Errorf("all-not-found err = %v, want errRecordNotFound", err)
	}
}

func TestMergeQueryErrors_EmptyInput(t *testing.T) {
	if err := mergeQueryErrors("x.test", nil); !errors.Is(err, dns_feature.ErrEmptyResponse) {
		t.Errorf("empty errs = %v, want ErrEmptyResponse", err)
	}
}

func TestMergeQueryErrors_DistinctErrorsCombined(t *testing.T) {
	e1 := errors.New("timeout")
	e2 := errors.New("refused")
	err := mergeQueryErrors("x.test", []error{e1, e2})
	if err == nil {
		t.Error("distinct errors should combine into non-nil")
	}
}

// --- ResolveIpOptionOverride (extended) ---

func TestResolveIpOptionOverride_AllStrategies(t *testing.T) {
	base := dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true, FakeEnable: true}
	cases := []struct {
		name     string
		strategy QueryStrategy
		v4, v6   bool
	}{
		{"USE_IP", QueryStrategy_USE_IP, true, true},
		{"USE_SYS", QueryStrategy_USE_SYS, true, true},
		{"USE_IP4", QueryStrategy_USE_IP4, true, false},
		{"USE_IP6", QueryStrategy_USE_IP6, false, true},
	}
	for _, c := range cases {
		got := ResolveIpOptionOverride(c.strategy, base)
		if got.IPv4Enable != c.v4 || got.IPv6Enable != c.v6 {
			t.Errorf("%s: got %+v, want v4=%v v6=%v", c.name, got, c.v4, c.v6)
		}
	}
}

// --- Fqdn ---

func TestFqdn(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "example.com."},
		{"example.com.", "example.com."},
		{"", "."},
	}
	for _, c := range cases {
		if got := Fqdn(c.in); got != c.want {
			t.Errorf("Fqdn(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --- IPRecord.getIPs ---

func TestIPRecord_GetIPs(t *testing.T) {
	// nil record → errRecordNotFound.
	if _, _, err := (*IPRecord)(nil).getIPs(); !errors.Is(err, errRecordNotFound) {
		t.Errorf("nil record err = %v, want errRecordNotFound", err)
	}
	// Empty IPs with success RCode → ErrEmptyResponse.
	r := &IPRecord{Expire: time.Now().Add(time.Second)}
	if _, _, err := r.getIPs(); !errors.Is(err, dns_feature.ErrEmptyResponse) {
		t.Errorf("empty record err = %v, want ErrEmptyResponse", err)
	}
}

// --- geodata IP filter integration via Client (parse-only smoke test) ---

// TestParseIPRules_Formats is a light sanity check that ParseIPRules accepts the
// common formats used in DNS expectedIPs / routing ip rules.
func TestParseIPRules_Formats(t *testing.T) {
	cases := [][]string{
		{"10.0.0.0/8"},
		{"10.0.0.0/8", "192.168.0.0/16"},
		{"::1/128"},
	}
	for _, c := range cases {
		if _, err := geodata.ParseIPRules(c); err != nil {
			t.Errorf("ParseIPRules(%v) err = %v", c, err)
		}
	}
}

func TestParseIPRules_RejectsBad(t *testing.T) {
	bad := []string{"not-an-ip", "10.0.0.0/33"} // prefix > 32
	if _, err := geodata.ParseIPRules(bad); err == nil {
		t.Error("ParseIPRules should reject invalid rules")
	}
}
