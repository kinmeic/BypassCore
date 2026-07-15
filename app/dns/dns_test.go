package dns

import (
	"context"
	goerrors "errors"
	"testing"

	"github.com/eugene/bypasscore/common/geodata"
	bcnet "github.com/eugene/bypasscore/common/net"
	dns_feature "github.com/eugene/bypasscore/features/dns"
)

type rawSelectionServer struct {
	name  string
	calls int
}

func (s *rawSelectionServer) Name() string       { return s.name }
func (*rawSelectionServer) IsDisableCache() bool { return true }
func (*rawSelectionServer) QueryIP(context.Context, string, dns_feature.IPOption) ([]bcnet.IP, uint32, error) {
	return nil, 0, dns_feature.ErrEmptyResponse
}
func (s *rawSelectionServer) QueryRaw(_ context.Context, query []byte) ([]byte, error) {
	s.calls++
	return append([]byte(nil), query...), nil
}

func TestLookupIPContextHonorsCancellation(t *testing.T) {
	server, err := New(context.Background(), &Config{
		QueryStrategy: QueryStrategy_USE_IP,
		StaticHosts: []*Config_HostMapping{{
			Domain: mustDomainRule(t, "cancel.test"), Ip: [][]byte{{192, 0, 2, 1}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = server.LookupIPContext(ctx, "cancel.test", dns_feature.IPOption{IPv4Enable: true})
	if !goerrors.Is(err, context.Canceled) {
		t.Fatalf("LookupIPContext error=%v, want context.Canceled", err)
	}
}

func TestLookupRawHonorsDomainSpecificFinalAndDefaultFallback(t *testing.T) {
	rules, err := geodata.ParseDomainRules([]string{"domain:cn"}, geodata.Domain_Substr)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := geodata.DomainReg.BuildDomainMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	direct := &rawSelectionServer{name: "direct"}
	remote := &rawSelectionServer{name: "remote"}
	server := &DNS{
		ctx:           context.Background(),
		clients:       []*Client{{server: direct, skipFallback: true, finalQuery: true}, {server: remote}},
		domainMatcher: matcher,
		matcherInfos:  []*DomainMatcherInfo{{clientIdx: 0, domainRule: "domain:cn"}},
	}

	if _, err := server.LookupRawContext(context.Background(), "www.example.com", []byte{1}); err != nil {
		t.Fatal(err)
	}
	if direct.calls != 0 || remote.calls != 1 {
		t.Fatalf("unmatched raw query used direct=%d remote=%d", direct.calls, remote.calls)
	}
	if _, err := server.LookupRawContext(context.Background(), "www.example.cn", []byte{2}); err != nil {
		t.Fatal(err)
	}
	if direct.calls != 1 || remote.calls != 1 {
		t.Fatalf("matched raw query used direct=%d remote=%d", direct.calls, remote.calls)
	}
}

func mustDomainRule(t *testing.T, domain string) *geodata.DomainRule {
	r, err := geodata.ParseDomainRule(domain, geodata.Domain_Full)
	if err != nil {
		t.Fatalf("ParseDomainRule(%s): %v", domain, err)
	}
	return r
}

func ipMustBe(s string) bcnet.IP {
	return bcnet.ParseAddress(s).IP()
}

// TestStaticHosts verifies host-mapping lookup and domain aliasing. This is a
// self-contained test of the hosts layer (no network needed).
func TestStaticHostsBuild(t *testing.T) {
	cfg := &Config{
		StaticHosts: []*Config_HostMapping{
			{
				Domain: mustDomainRule(t, "local.test"),
				Ip:     [][]byte{{127, 0, 0, 1}},
			},
			{
				Domain:        mustDomainRule(t, "alias.test"),
				ProxiedDomain: "local.test",
			},
		},
	}

	hosts, err := NewStaticHosts(cfg.StaticHosts)
	if err != nil {
		t.Fatalf("NewStaticHosts: %v", err)
	}

	// Direct lookup of local.test should return 127.0.0.1.
	addrs, err := hosts.Lookup("local.test", dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil {
		t.Fatalf("Lookup local.test: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("expected 1 addr, got %d", len(addrs))
	}
	if !addrs[0].IP().Equal(ipMustBe("127.0.0.1")) {
		t.Fatalf("expected 127.0.0.1, got %s", addrs[0].IP())
	}

	// Alias lookup of alias.test should resolve to local.test -> 127.0.0.1.
	addrs, err = hosts.Lookup("alias.test", dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil {
		t.Fatalf("Lookup alias.test: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("expected 1 addr from alias, got %d", len(addrs))
	}
	if !addrs[0].IP().Equal(ipMustBe("127.0.0.1")) {
		t.Fatalf("expected 127.0.0.1 from alias, got %s", addrs[0].IP())
	}

	// Unknown domain returns nil, nil.
	addrs, _ = hosts.Lookup("unknown.test", dns_feature.IPOption{IPv4Enable: true})
	if addrs != nil {
		t.Fatalf("expected nil for unknown domain, got %v", addrs)
	}
}

// TestResolveIpOptionOverride verifies query-strategy filtering.
func TestResolveIpOptionOverride(t *testing.T) {
	base := dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true, FakeEnable: true}

	got := ResolveIpOptionOverride(QueryStrategy_USE_IP, base)
	if !got.IPv4Enable || !got.IPv6Enable {
		t.Error("USE_IP should not filter")
	}

	got = ResolveIpOptionOverride(QueryStrategy_USE_IP4, base)
	if !got.IPv4Enable || got.IPv6Enable {
		t.Error("USE_IP4 should keep v4, drop v6")
	}

	got = ResolveIpOptionOverride(QueryStrategy_USE_IP6, base)
	if got.IPv4Enable || !got.IPv6Enable {
		t.Error("USE_IP6 should drop v4, keep v6")
	}
}
