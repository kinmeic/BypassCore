package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	bcnet "github.com/eugene/bypasscore/common/net"
	dns_feature "github.com/eugene/bypasscore/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type delayedCachedNameserver struct {
	cache   *CacheController
	started chan struct{}
	once    sync.Once
}

func (s *delayedCachedNameserver) getCacheController() *CacheController { return s.cache }

func (s *delayedCachedNameserver) sendQuery(_ context.Context, _ chan<- error, fqdn string, option dns_feature.IPOption) {
	s.once.Do(func() { close(s.started) })
	go func() {
		time.Sleep(40 * time.Millisecond)
		if option.IPv4Enable {
			s.cache.updateRecord(&dnsRequest{reqType: dnsmessage.TypeA, domain: fqdn, start: time.Now()},
				&IPRecord{IP: []bcnet.IP{{192, 0, 2, 1}}, Expire: time.Now().Add(time.Minute)})
		}
	}()
}

func TestFetchCancellationIsPerWaiter(t *testing.T) {
	server := &delayedCachedNameserver{
		cache:   NewCacheController("test", true, false, 0),
		started: make(chan struct{}),
	}
	defer server.cache.Close()

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, _, err := fetch(firstCtx, server, "example.test.", dns_feature.IPOption{IPv4Enable: true})
		firstDone <- err
	}()
	<-server.started

	secondDone := make(chan result, 1)
	go func() {
		ips, ttl, err := fetch(context.Background(), server, "example.test.", dns_feature.IPOption{IPv4Enable: true})
		secondDone <- result{ips: ips, ttl: ttl, error: err}
	}()
	cancelFirst()

	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("first waiter error = %v, want context.Canceled", err)
	}
	second := <-secondDone
	if second.error != nil || len(second.ips) != 1 || second.ips[0].String() != "192.0.2.1" {
		t.Fatalf("second waiter = ips %v, ttl %d, err %v", second.ips, second.ttl, second.error)
	}
}

func TestFindRecordsReturnsSnapshot(t *testing.T) {
	cache := NewCacheController("test", false, false, 0)
	defer cache.Close()
	a := &IPRecord{IP: []bcnet.IP{{192, 0, 2, 1}}, Expire: time.Now().Add(-time.Second)}
	cache.ips["example.test."] = &record{A: a}

	snapshot := cache.findRecords("example.test.")
	cache.writeAndShrink([]string{"example.test."})
	if snapshot == nil || snapshot.A != a {
		t.Fatal("record snapshot was mutated by cache cleanup")
	}
	if cache.findRecords("example.test.") != nil {
		t.Fatal("expired cache entry was not removed")
	}
}

type partialCachedNameserver struct{ cache *CacheController }

func (s *partialCachedNameserver) getCacheController() *CacheController { return s.cache }
func (s *partialCachedNameserver) sendQuery(_ context.Context, failures chan<- error, fqdn string, option dns_feature.IPOption) {
	if option.IPv6Enable {
		failures <- errors.New("AAAA exchange failed")
	}
	if option.IPv4Enable {
		go func() {
			time.Sleep(10 * time.Millisecond) // Failure arrives before A succeeds.
			s.cache.updateRecord(&dnsRequest{reqType: dnsmessage.TypeA, domain: fqdn, start: time.Now()},
				&IPRecord{IP: []bcnet.IP{{192, 0, 2, 1}}, Expire: time.Now().Add(time.Minute)})
		}()
	}
}

func TestFetchPreservesSuccessfulFamilyAfterOtherFamilyFails(t *testing.T) {
	server := &partialCachedNameserver{cache: NewCacheController("partial", true, false, 0)}
	defer server.cache.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	got := doFetch(ctx, server, "example.test.", dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true})
	if got.error != nil || len(got.ips) != 1 || got.ips[0].String() != "192.0.2.1" || got.ttl < 50 {
		t.Fatalf("partial lookup = %+v", got)
	}
}

func TestCacheCloseRejectsLateResponsesAndNewQueries(t *testing.T) {
	cache := NewCacheController("closed", false, false, 0)
	_ = cache.Close()
	cache.updateRecord(&dnsRequest{reqType: dnsmessage.TypeA, domain: "example.test.", start: time.Now()},
		&IPRecord{IP: []bcnet.IP{{192, 0, 2, 1}}, Expire: time.Now().Add(time.Minute)})
	if cache.findRecords("example.test.") != nil {
		t.Fatal("late response repopulated a closed cache")
	}
	server := &partialCachedNameserver{cache: cache}
	if _, _, err := queryIP(t.Context(), server, "example.test", dns_feature.IPOption{IPv4Enable: true}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("lookup after Close = %v", err)
	}
}
