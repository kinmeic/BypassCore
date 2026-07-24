package geodata

import (
	stdnet "net"
	"testing"

	"go4.org/netipx"
)

func TestReverseEmptyAddressFamilyMatches(t *testing.T) {
	var builder netipx.IPSetBuilder
	set, err := builder.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	matcher := newHeuristicIPMatcher(&IPSet{
		ipv4: set,
		ipv6: set,
		max4: 0xff,
		max6: 0xff,
	}, true)
	if !matcher.Match(stdnet.ParseIP("192.0.2.1")) {
		t.Fatal("reversed empty IPv4 set should match an IPv4 address")
	}
	if !matcher.Match(stdnet.ParseIP("2001:db8::1")) {
		t.Fatal("reversed empty IPv6 set should match an IPv6 address")
	}
}

func TestParseDomainRejectsNonLDHPatterns(t *testing.T) {
	for _, value := range []string{"bad_name.example", "bad/name.example", "bad name.example"} {
		if _, err := parseDomain(&Domain{Type: Domain_Domain, Value: value}); err == nil {
			t.Errorf("invalid domain pattern %q was accepted", value)
		}
	}
}
