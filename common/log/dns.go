package log

import (
	"net"
	"strings"
	"time"
)

// DNSLog is a log message describing a DNS query result.
type DNSLog struct {
	Server  string
	Domain  string
	Result  []net.IP
	Status  dnsStatus
	Elapsed time.Duration
	Error   error
}

// String implements Message.
func (l *DNSLog) String() string {
	var b strings.Builder
	b.WriteString(l.Server)
	b.WriteString(" ")
	b.WriteString(string(l.Status))
	b.WriteString(" ")
	b.WriteString(l.Domain)
	b.WriteString(" -> [")
	b.WriteString(joinNetIP(l.Result))
	b.WriteString("]")
	if l.Elapsed > 0 {
		b.WriteString(" ")
		b.WriteString(l.Elapsed.String())
	}
	if l.Error != nil {
		b.WriteString(" <")
		b.WriteString(l.Error.Error())
		b.WriteString(">")
	}
	return b.String()
}

type dnsStatus string

// DNS query status markers.
var (
	DNSQueried        = dnsStatus("got answer:")
	DNSCacheHit       = dnsStatus("cache HIT:")
	DNSCacheOptimiste = dnsStatus("cache OPTIMISTE:")
)

func joinNetIP(ips []net.IP) string {
	if len(ips) == 0 {
		return ""
	}
	sips := make([]string, 0, len(ips))
	for _, ip := range ips {
		sips = append(sips, ip.String())
	}
	return strings.Join(sips, ", ")
}
