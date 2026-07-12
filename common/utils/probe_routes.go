package utils

import (
	"net"
	"sync"
	"time"
)

// CheckRoutes reports whether IPv4 and IPv6 connectivity is available, by
// attempting UDP dials to well-known nameservers. Results are cached briefly.
func CheckRoutes() (bool, bool) {
	return routeCache.get()
}

func probeRoutes() (ipv4 bool, ipv6 bool) {
	if conn, err := net.Dial("udp4", "192.33.4.12:53"); err == nil {
		ipv4 = true
		conn.Close()
	}
	if conn, err := net.Dial("udp6", "[2001:500:2::c]:53"); err == nil {
		ipv6 = true
		conn.Close()
	}
	return
}

type routeState struct {
	sync.RWMutex
	expire     time.Time
	ipv4, ipv6 bool
}

var routeCache = &routeState{}

func (r *routeState) get() (bool, bool) {
	r.RLock()
	if r.expire.After(time.Now()) {
		v4, v6 := r.ipv4, r.ipv6
		r.RUnlock()
		return v4, v6
	}
	r.RUnlock()

	r.Lock()
	defer r.Unlock()
	if r.expire.After(time.Now()) { // double-check
		return r.ipv4, r.ipv6
	}
	r.ipv4, r.ipv6 = probeRoutes()
	r.expire = time.Now().Add(100 * time.Millisecond)
	return r.ipv4, r.ipv6
}
