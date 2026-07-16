package inbound

import (
	"net/netip"
	"testing"
	"time"
)

func TestDNSAccessPolicyCIDRs(t *testing.T) {
	allowed, limiter, global, err := newDNSAccessPolicy(&Config{
		DNSAllowedClients:   []string{"127.0.0.0/8", "2001:db8::/32"},
		DNSQueriesPerSecond: 2,
		DNSQueryBurst:       3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if limiter == nil || global != nil || !clientAllowed(netip.MustParseAddr("127.0.0.1"), allowed) ||
		!clientAllowed(netip.MustParseAddr("2001:db8::1"), allowed) ||
		clientAllowed(netip.MustParseAddr("192.0.2.1"), allowed) {
		t.Fatalf("unexpected DNS access policy: allowed=%v limiter=%v", allowed, limiter)
	}
}

func TestDNSRateLimiterTokenBucket(t *testing.T) {
	_, limiter, _, err := newDNSAccessPolicy(&Config{DNSQueriesPerSecond: 2, DNSQueryBurst: 2})
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.1")
	now := time.Unix(100, 0)
	for i := 0; i < 2; i++ {
		if !limiter.allow(ip, now) {
			t.Fatal("initial burst was not available")
		}
	}
	if limiter.allow(ip, now) {
		t.Fatal("rate limiter exceeded burst")
	}
	if !limiter.allow(ip, now.Add(500*time.Millisecond)) {
		t.Fatal("rate limiter did not replenish one token")
	}
}

func TestDNSGlobalRateLimiter(t *testing.T) {
	_, _, limiter, err := newDNSAccessPolicy(&Config{DNSGlobalQueriesPerSecond: 1, DNSGlobalQueryBurst: 2})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	for i := 0; i < 2; i++ {
		if !limiter.allow(now) {
			t.Fatal("global DNS burst was not available")
		}
	}
	if limiter.allow(now) {
		t.Fatal("global DNS burst was exceeded")
	}
	if !limiter.allow(now.Add(time.Second)) {
		t.Fatal("global DNS token was not replenished")
	}
}

func TestDNSAccessPolicyRejectsInvalidConfiguration(t *testing.T) {
	for _, cfg := range []Config{
		{DNSAllowedClients: []string{"not-a-prefix"}},
		{DNSQueriesPerSecond: -1},
		{DNSQueryBurst: 1},
	} {
		if _, _, _, err := newDNSAccessPolicy(&cfg); err == nil {
			t.Fatalf("invalid DNS access configuration accepted: %+v", cfg)
		}
	}
}
