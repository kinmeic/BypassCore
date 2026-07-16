// Package inbound implements transparent proxy and DNS listeners. Transparent
// connections are dispatched to the router→outbound flow; DNS queries are
// answered by the configured internal DNS client.
//
// This replaces xray-core's dokodemo-door inbound + app/proxyman/inbound/worker.
package inbound

// DNSRuleConfig controls how a DNS inbound handles matching questions. Rules
// are evaluated in order. Domain syntax matches routing rules (domain:, full:,
// regexp:, geosite:); qType accepts names such as A, AAAA, TXT or numeric types.
type DNSRuleConfig struct {
	Domain []string `json:"domain,omitempty"`
	QType  []string `json:"qType,omitempty"`
	Action string   `json:"action"`
	RCode  uint16   `json:"rcode,omitempty"`
}

// Config describes an inbound listener.
type Config struct {
	// Tag is the inbound identifier (e.g. "tcp_redir").
	Tag string `json:"tag"`
	// Type is the listener type: "tproxy", "redirect", or "dns".
	//   "redirect": iptables REDIRECT mode, uses SO_ORIGINAL_DST.
	//   "tproxy":   uses IP_TRANSPARENT and the socket's local address.
	Type string `json:"type"`
	// Listen is the bind address (e.g. "0.0.0.0").
	Listen string `json:"listen"`
	// Port is the listen port (e.g. 12345, the tproxy/redirect target).
	Port int `json:"port"`
	// Network is the protocol: "tcp", "udp", or "tcp,udp".
	// UDP is supported only with TPROXY/IP_TRANSPARENT.
	// A DNS inbound supports both ordinary TCP and UDP sockets.
	Network string `json:"network"`
	// Sniffing enables TLS/HTTP domain sniffing for routing while preserving
	// the kernel-provided destination used for the actual outbound connection.
	Sniffing bool `json:"sniffing"`
	// SniffingTimeoutMs and SniffingMaxBytes bound TCP protocol detection.
	// Zero uses 500 ms and 32768 bytes.
	SniffingTimeoutMs int `json:"sniffingTimeoutMs,omitempty"`
	SniffingMaxBytes  int `json:"sniffingMaxBytes,omitempty"`
	// UDPSniffWaitMs and UDPSniffMaxPackets bound multi-packet QUIC detection.
	// Zero uses 25 ms and 4 packets.
	UDPSniffWaitMs     int `json:"udpSniffWaitMs,omitempty"`
	UDPSniffMaxPackets int `json:"udpSniffMaxPackets,omitempty"`
	// MaxConcurrentQueries bounds in-flight DNS lookups. Zero uses 256.
	// This field is used only by type=dns.
	MaxConcurrentQueries int `json:"maxConcurrentQueries,omitempty"`
	// MaxTCPConnections bounds concurrently open DNS-over-TCP connections.
	// Zero uses 128. This field is used only by type=dns.
	MaxTCPConnections int `json:"maxTCPConnections,omitempty"`
	// MaxQueryBytes bounds a single UDP or TCP DNS request before parsing.
	// Zero uses 4096; valid explicit values are 512..65535.
	MaxQueryBytes int `json:"maxQueryBytes,omitempty"`
	// DNSAllowedClients limits a DNS inbound to the listed IPv4/IPv6 CIDRs.
	// Empty preserves compatibility and permits every client reaching the
	// socket. Prefer explicit LAN/loopback prefixes on non-loopback listeners.
	DNSAllowedClients []string `json:"dnsAllowedClients,omitempty"`
	// DNSQueriesPerSecond enables a bounded per-source token bucket. Zero
	// disables rate limiting. DNSQueryBurst defaults to this value when zero.
	DNSQueriesPerSecond int `json:"dnsQueriesPerSecond,omitempty"`
	DNSQueryBurst       int `json:"dnsQueryBurst,omitempty"`
	// DNSGlobalQueriesPerSecond adds a listener-wide token bucket, which is
	// effective even when UDP source addresses are spoofed.
	DNSGlobalQueriesPerSecond int `json:"dnsGlobalQueriesPerSecond,omitempty"`
	DNSGlobalQueryBurst       int `json:"dnsGlobalQueryBurst,omitempty"`
	// DNSRules use Xray-compatible direct/drop/return/hijack semantics.
	DNSRules []DNSRuleConfig `json:"dnsRules,omitempty"`
	// DNSRawCacheEntries bounds non-A/AAAA wire-response caching. Zero uses
	// 4096; a negative value disables it. Max TTL zero uses 3600 seconds.
	DNSRawCacheEntries       int `json:"dnsRawCacheEntries,omitempty"`
	DNSRawCacheMaxTTLSeconds int `json:"dnsRawCacheMaxTTLSeconds,omitempty"`
	// DNSRawCacheMaxBytes bounds total key/response bytes. Zero uses 16 MiB.
	DNSRawCacheMaxBytes int `json:"dnsRawCacheMaxBytes,omitempty"`
	// DNS secure-listener settings. Type=dot and type=doh require both files.
	DNSCertificateFile string `json:"dnsCertificateFile,omitempty"`
	DNSKeyFile         string `json:"dnsKeyFile,omitempty"`
	// DNSDoHPath defaults to /dns-query for type=doh.
	DNSDoHPath string `json:"dnsDoHPath,omitempty"`
	// UDPMaxSessions bounds all active UDP TPROXY flows for this inbound.
	// Zero uses 1024. This field is used only by type=tproxy, network=udp.
	UDPMaxSessions int `json:"udpMaxSessions,omitempty"`
	// UDPMaxSessionsPerSource prevents one source IP from exhausting the
	// global session budget. Zero uses min(256, udpMaxSessions).
	UDPMaxSessionsPerSource int `json:"udpMaxSessionsPerSource,omitempty"`
	// UDPSessionQueueBytes bounds queued datagram bytes per flow. Zero uses
	// 65536. Packets that exceed the remaining budget are dropped.
	UDPSessionQueueBytes int `json:"udpSessionQueueBytes,omitempty"`
	// UDPSessionQueuePackets bounds queued datagrams per flow. Zero uses 64.
	UDPSessionQueuePackets int `json:"udpSessionQueuePackets,omitempty"`
	// UDPSessionIdleTimeoutSeconds controls inactive flow eviction. Zero uses
	// 120 seconds.
	UDPSessionIdleTimeoutSeconds int `json:"udpSessionIdleTimeoutSeconds,omitempty"`
}
