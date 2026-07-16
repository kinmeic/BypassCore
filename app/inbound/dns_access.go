package inbound

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	maximumDNSRate             = 1_000_000
	maximumDNSRateClients      = 4096
	dnsRateClientIdleRetention = 5 * time.Minute
)

type dnsRateEntry struct {
	tokens   float64
	lastSeen time.Time
}

// dnsRateLimiter is a bounded per-source token bucket. The entry cap is
// essential for UDP because source addresses can be spoofed.
type dnsRateLimiter struct {
	mu         sync.Mutex
	rate       float64
	burst      float64
	maxClients int
	clients    map[netip.Addr]dnsRateEntry
	checks     uint64
}

type dnsGlobalRateLimiter struct {
	mu       sync.Mutex
	rate     float64
	burst    float64
	tokens   float64
	lastSeen time.Time
}

func newDNSAccessPolicy(cfg *Config) ([]netip.Prefix, *dnsRateLimiter, *dnsGlobalRateLimiter, error) {
	allowed := make([]netip.Prefix, 0, len(cfg.DNSAllowedClients))
	for _, raw := range cfg.DNSAllowedClients {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("DNS inbound: invalid dnsAllowedClients prefix %q: %w", raw, err)
		}
		allowed = append(allowed, prefix.Masked())
	}
	if cfg.DNSQueriesPerSecond < 0 || cfg.DNSQueriesPerSecond > maximumDNSRate {
		return nil, nil, nil, fmt.Errorf("DNS inbound: dnsQueriesPerSecond must be between 0 and %d", maximumDNSRate)
	}
	if cfg.DNSQueryBurst < 0 || cfg.DNSQueryBurst > maximumDNSRate {
		return nil, nil, nil, fmt.Errorf("DNS inbound: dnsQueryBurst must be between 0 and %d", maximumDNSRate)
	}
	if cfg.DNSGlobalQueriesPerSecond < 0 || cfg.DNSGlobalQueriesPerSecond > maximumDNSRate {
		return nil, nil, nil, fmt.Errorf("DNS inbound: dnsGlobalQueriesPerSecond must be between 0 and %d", maximumDNSRate)
	}
	if cfg.DNSGlobalQueryBurst < 0 || cfg.DNSGlobalQueryBurst > maximumDNSRate {
		return nil, nil, nil, fmt.Errorf("DNS inbound: dnsGlobalQueryBurst must be between 0 and %d", maximumDNSRate)
	}
	if cfg.DNSQueriesPerSecond == 0 && cfg.DNSQueryBurst != 0 {
		return nil, nil, nil, fmt.Errorf("DNS inbound: dnsQueryBurst requires dnsQueriesPerSecond")
	}
	if cfg.DNSGlobalQueriesPerSecond == 0 && cfg.DNSGlobalQueryBurst != 0 {
		return nil, nil, nil, fmt.Errorf("DNS inbound: dnsGlobalQueryBurst requires dnsGlobalQueriesPerSecond")
	}
	var perSource *dnsRateLimiter
	if cfg.DNSQueriesPerSecond > 0 {
		burst := cfg.DNSQueryBurst
		if burst == 0 {
			burst = cfg.DNSQueriesPerSecond
		}
		perSource = &dnsRateLimiter{
			rate: float64(cfg.DNSQueriesPerSecond), burst: float64(burst),
			maxClients: maximumDNSRateClients, clients: make(map[netip.Addr]dnsRateEntry),
		}
	}
	var global *dnsGlobalRateLimiter
	if cfg.DNSGlobalQueriesPerSecond > 0 {
		burst := cfg.DNSGlobalQueryBurst
		if burst == 0 {
			burst = cfg.DNSGlobalQueriesPerSecond
		}
		global = &dnsGlobalRateLimiter{rate: float64(cfg.DNSGlobalQueriesPerSecond), burst: float64(burst), tokens: float64(burst)}
	}
	return allowed, perSource, global, nil
}

func clientIP(address net.Addr) (netip.Addr, bool) {
	switch addr := address.(type) {
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(addr.IP)
		return ip.Unmap(), ok
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(addr.IP)
		return ip.Unmap(), ok
	default:
		return netip.Addr{}, false
	}
}

func clientAllowed(ip netip.Addr, prefixes []netip.Prefix) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (l *dnsRateLimiter) allow(ip netip.Addr, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.checks++
	if l.checks%256 == 0 {
		l.removeIdle(now)
	}
	entry, exists := l.clients[ip]
	if !exists {
		if len(l.clients) >= l.maxClients {
			l.removeIdle(now)
			if len(l.clients) >= l.maxClients {
				return false
			}
		}
		entry = dnsRateEntry{tokens: l.burst, lastSeen: now}
	} else {
		entry.tokens += now.Sub(entry.lastSeen).Seconds() * l.rate
		if entry.tokens > l.burst {
			entry.tokens = l.burst
		}
		entry.lastSeen = now
	}
	if entry.tokens < 1 {
		l.clients[ip] = entry
		return false
	}
	entry.tokens--
	l.clients[ip] = entry
	return true
}

func (l *dnsGlobalRateLimiter) allow(now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lastSeen.IsZero() {
		l.lastSeen = now
	} else {
		l.tokens += now.Sub(l.lastSeen).Seconds() * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.lastSeen = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// removeIdle requires l.mu.
func (l *dnsRateLimiter) removeIdle(now time.Time) {
	cutoff := now.Add(-dnsRateClientIdleRetention)
	for ip, entry := range l.clients {
		if entry.lastSeen.Before(cutoff) {
			delete(l.clients, ip)
		}
	}
}
