package inbound

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	defaultDNSRawCacheEntries  = 4096
	defaultDNSRawCacheMaxTTL   = time.Hour
	defaultDNSRawCacheMaxBytes = 16 * 1024 * 1024
	maximumDNSRawCacheMaxBytes = 1024 * 1024 * 1024
)

type dnsRawCacheEntry struct {
	key      string
	response []byte
	stored   time.Time
	expires  time.Time
	size     int
}

type dnsRawCache struct {
	mu       sync.Mutex
	max      int
	maxTTL   time.Duration
	maxBytes int
	bytes    int
	entries  map[string]*list.Element
	lru      list.List
}

func newDNSRawCache(entries, maxTTLSeconds int) (*dnsRawCache, error) {
	return newDNSRawCacheWithLimit(entries, maxTTLSeconds, 0)
}

func newDNSRawCacheWithLimit(entries, maxTTLSeconds, maxBytes int) (*dnsRawCache, error) {
	if entries < 0 {
		return nil, nil
	}
	if entries == 0 {
		entries = defaultDNSRawCacheEntries
	}
	if entries > 65535 {
		return nil, fmt.Errorf("DNS inbound: dnsRawCacheEntries must be between -1 and 65535")
	}
	if maxBytes == 0 {
		maxBytes = defaultDNSRawCacheMaxBytes
	}
	if maxBytes < 1024 || maxBytes > maximumDNSRawCacheMaxBytes {
		return nil, fmt.Errorf("DNS inbound: dnsRawCacheMaxBytes must be between 1024 and %d", maximumDNSRawCacheMaxBytes)
	}
	maxTTL := defaultDNSRawCacheMaxTTL
	if maxTTLSeconds != 0 {
		if maxTTLSeconds < 1 || maxTTLSeconds > 7*24*60*60 {
			return nil, fmt.Errorf("DNS inbound: dnsRawCacheMaxTTLSeconds must be between 1 and %d", 7*24*60*60)
		}
		maxTTL = time.Duration(maxTTLSeconds) * time.Second
	}
	return &dnsRawCache{max: entries, maxTTL: maxTTL, maxBytes: maxBytes, entries: make(map[string]*list.Element)}, nil
}

func rawCacheKey(query []byte) (string, bool) {
	if len(query) < 12 {
		return "", false
	}
	key := append([]byte(nil), query...)
	key[0], key[1] = 0, 0
	return string(key), true
}

func (c *dnsRawCache) get(query []byte, now time.Time) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	key, ok := rawCacheKey(query)
	if !ok {
		return nil, false
	}
	c.mu.Lock()
	element := c.entries[key]
	if element == nil {
		c.mu.Unlock()
		return nil, false
	}
	entry := element.Value.(*dnsRawCacheEntry)
	if !now.Before(entry.expires) {
		c.removeElement(element)
		c.mu.Unlock()
		return nil, false
	}
	c.lru.MoveToFront(element)
	wire := append([]byte(nil), entry.response...)
	stored, expires := entry.stored, entry.expires
	c.mu.Unlock()

	var response, request dnsmessage.Message
	if response.Unpack(wire) != nil || request.Unpack(query) != nil {
		return nil, false
	}
	response.ID = request.ID
	response.RecursionDesired = request.RecursionDesired
	response.CheckingDisabled = request.CheckingDisabled
	response.Questions = append([]dnsmessage.Question(nil), request.Questions...)
	elapsed := uint32(now.Sub(stored) / time.Second)
	remaining := uint32(expires.Sub(now) / time.Second)
	adjustResourceTTLs(response.Answers, elapsed, remaining)
	adjustResourceTTLs(response.Authorities, elapsed, remaining)
	adjustResourceTTLs(response.Additionals, elapsed, remaining)
	packed, err := response.Pack()
	return packed, err == nil
}

func adjustResourceTTLs(resources []dnsmessage.Resource, elapsed, remaining uint32) {
	for i := range resources {
		if resources[i].Header.Type == dnsmessage.TypeOPT {
			continue
		}
		if resources[i].Header.TTL > elapsed {
			resources[i].Header.TTL -= elapsed
		} else {
			resources[i].Header.TTL = 0
		}
		if resources[i].Header.TTL > remaining {
			resources[i].Header.TTL = remaining
		}
	}
}

func (c *dnsRawCache) put(query, response []byte, now time.Time) {
	if c == nil || len(response) < 12 {
		return
	}
	key, ok := rawCacheKey(query)
	if !ok {
		return
	}
	if binary.BigEndian.Uint16(query[:2]) != binary.BigEndian.Uint16(response[:2]) {
		return
	}
	var message dnsmessage.Message
	if message.Unpack(response) != nil || message.Truncated ||
		(message.RCode != dnsmessage.RCodeSuccess && message.RCode != dnsmessage.RCodeNameError) {
		return
	}
	ttl, ok := rawResponseTTL(&message)
	if !ok || ttl == 0 {
		return
	}
	duration := time.Duration(ttl) * time.Second
	if duration > c.maxTTL {
		duration = c.maxTTL
	}
	wire := append([]byte(nil), response...)
	wire[0], wire[1] = 0, 0
	size := len(key) + len(wire)
	if size > c.maxBytes {
		return
	}
	entry := &dnsRawCacheEntry{key: key, response: wire, stored: now, expires: now.Add(duration), size: size}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.entries[key]; old != nil {
		c.bytes -= old.Value.(*dnsRawCacheEntry).size
		old.Value = entry
		c.bytes += entry.size
		c.lru.MoveToFront(old)
	} else {
		element := c.lru.PushFront(entry)
		c.entries[key] = element
		c.bytes += entry.size
	}
	for len(c.entries) > c.max || c.bytes > c.maxBytes {
		c.removeElement(c.lru.Back())
	}
}

func rawResponseTTL(message *dnsmessage.Message) (uint32, bool) {
	minTTL := ^uint32(0)
	found := false
	visit := func(resources []dnsmessage.Resource) {
		for _, resource := range resources {
			if resource.Header.Type == dnsmessage.TypeOPT {
				continue
			}
			ttl := resource.Header.TTL
			if soa, ok := resource.Body.(*dnsmessage.SOAResource); ok && soa.MinTTL < ttl {
				ttl = soa.MinTTL
			}
			if ttl < minTTL {
				minTTL = ttl
			}
			found = true
		}
	}
	visit(message.Answers)
	visit(message.Authorities)
	visit(message.Additionals)
	return minTTL, found
}

func (c *dnsRawCache) removeElement(element *list.Element) {
	if element == nil {
		return
	}
	entry := element.Value.(*dnsRawCacheEntry)
	delete(c.entries, entry.key)
	c.bytes -= entry.size
	c.lru.Remove(element)
}
