package inbound

import (
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func rawTXTResponse(t testing.TB, query []byte, ttl uint32, text string) []byte {
	t.Helper()
	message := unpackDNS(t, query)
	message.Response = true
	message.RecursionAvailable = true
	message.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: ttl},
		Body:   &dnsmessage.TXTResource{TXT: []string{text}},
	}}
	response, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestDNSRawCacheHitPreservesRequestAndTTL(t *testing.T) {
	cache, err := newDNSRawCache(2, 60)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	query := dnsQuery(t, 1, dnsmessage.TypeTXT)
	cache.put(query, rawTXTResponse(t, query, 30, "cached"), now)

	second := append([]byte(nil), query...)
	second[0], second[1] = 0, 2
	response, ok := cache.get(second, now.Add(5*time.Second))
	if !ok {
		t.Fatal("raw cache miss")
	}
	message := unpackDNS(t, response)
	if message.ID != 2 || len(message.Answers) != 1 || message.Answers[0].Header.TTL != 25 {
		t.Fatalf("cached response id=%d answers=%d ttl=%d", message.ID, len(message.Answers), message.Answers[0].Header.TTL)
	}
	if _, ok := cache.get(second, now.Add(31*time.Second)); ok {
		t.Fatal("expired raw cache entry was served")
	}
}

func TestDNSRawCacheLRUAndDisable(t *testing.T) {
	cache, _ := newDNSRawCache(1, 60)
	now := time.Unix(100, 0)
	first := dnsQuery(t, 1, dnsmessage.TypeTXT)
	second := dnsQuery(t, 2, dnsmessage.TypeMX)
	cache.put(first, rawTXTResponse(t, first, 30, "first"), now)
	cache.put(second, rawTXTResponse(t, second, 30, "second"), now)
	if _, ok := cache.get(first, now); ok {
		t.Fatal("LRU cache did not evict oldest entry")
	}
	if disabled, err := newDNSRawCache(-1, 0); err != nil || disabled != nil {
		t.Fatalf("disable cache=%v err=%v", disabled, err)
	}
}

func TestDNSRawCacheByteLimit(t *testing.T) {
	cache, err := newDNSRawCacheWithLimit(10, 60, 1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	for i := uint16(1); i <= 10; i++ {
		query := dnsQuery(t, i, dnsmessage.Type(100+i))
		cache.put(query, rawTXTResponse(t, query, 30, string(make([]byte, 200))), now)
		if cache.bytes > cache.maxBytes {
			t.Fatalf("cache bytes=%d exceeds limit=%d", cache.bytes, cache.maxBytes)
		}
	}
	if len(cache.entries) >= 10 {
		t.Fatal("byte budget did not evict entries before the entry-count limit")
	}
}

func BenchmarkDNSRawCacheHit(b *testing.B) {
	cache, _ := newDNSRawCache(4096, 3600)
	query := dnsQuery(b, 1, dnsmessage.TypeTXT)
	cache.put(query, rawTXTResponse(b, query, 300, "cached"), time.Now())
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		query[0], query[1] = byte(i>>8), byte(i)
		if _, ok := cache.get(query, time.Now()); !ok {
			b.Fatal("cache miss")
		}
	}
}
