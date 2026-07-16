package router

import (
	"container/list"
	"strconv"
	"sync"
	"time"

	commonmetrics "github.com/eugene/bypasscore/common/metrics"
	bcnet "github.com/eugene/bypasscore/common/net"
	"golang.org/x/sync/singleflight"
)

const (
	processCacheCapacity = 4096
	processCacheTTL      = 500 * time.Millisecond
	processErrorCacheTTL = 100 * time.Millisecond
)

type processCacheKey struct {
	network    string
	sourceIP   string
	sourcePort uint16
	destIP     string
	destPort   uint16
}

type processCacheValue struct {
	key     processCacheKey
	pid     int
	name    string
	path    string
	err     error
	expires time.Time
}

type processLookupCache struct {
	mu      sync.Mutex
	entries map[processCacheKey]*list.Element
	lru     list.List
	flight  singleflight.Group
}

var (
	processCache = newProcessLookupCache()
	findProcess  = bcnet.FindProcess
)

func newProcessLookupCache() *processLookupCache {
	return &processLookupCache{entries: make(map[processCacheKey]*list.Element)}
}

func cachedFindProcess(network, sourceIP string, sourcePort uint16, destIP string, destPort uint16) (int, string, string, error) {
	key := processCacheKey{network: network, sourceIP: sourceIP, sourcePort: sourcePort, destIP: destIP, destPort: destPort}
	now := time.Now()
	processCache.mu.Lock()
	if element := processCache.entries[key]; element != nil {
		value := element.Value.(*processCacheValue)
		if now.Before(value.expires) {
			processCache.lru.MoveToFront(element)
			processCache.mu.Unlock()
			commonmetrics.Inc("bypasscore_process_lookup_cache_total", "result", "hit")
			return value.pid, value.name, value.path, value.err
		}
		processCache.remove(element)
	}
	processCache.mu.Unlock()
	commonmetrics.Inc("bypasscore_process_lookup_cache_total", "result", "miss")

	lookup, _, _ := processCache.flight.Do(processCacheFlightKey(key), func() (any, error) {
		pid, name, path, err := findProcess(network, sourceIP, sourcePort, destIP, destPort)
		ttl := processCacheTTL
		if err != nil {
			ttl = processErrorCacheTTL
		}
		value := &processCacheValue{key: key, pid: pid, name: name, path: path, err: err, expires: time.Now().Add(ttl)}
		processCache.mu.Lock()
		if old := processCache.entries[key]; old != nil {
			old.Value = value
			processCache.lru.MoveToFront(old)
		} else {
			element := processCache.lru.PushFront(value)
			processCache.entries[key] = element
		}
		for len(processCache.entries) > processCacheCapacity {
			processCache.remove(processCache.lru.Back())
		}
		processCache.mu.Unlock()
		return value, nil
	})
	value := lookup.(*processCacheValue)
	return value.pid, value.name, value.path, value.err
}

func processCacheFlightKey(key processCacheKey) string {
	return key.network + "\x00" + key.sourceIP + "\x00" + strconv.FormatUint(uint64(key.sourcePort), 10) +
		"\x00" + key.destIP + "\x00" + strconv.FormatUint(uint64(key.destPort), 10)
}

func (c *processLookupCache) remove(element *list.Element) {
	if element == nil {
		return
	}
	value := element.Value.(*processCacheValue)
	delete(c.entries, value.key)
	c.lru.Remove(element)
}
