// Package inbound implements transparent proxy and DNS listeners. Transparent
// connections are dispatched to the router→outbound flow; DNS queries are
// answered by the configured internal DNS client.
//
// This replaces xray-core's dokodemo-door inbound + app/proxyman/inbound/worker.
package inbound

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
	// MaxConcurrentQueries bounds in-flight DNS lookups. Zero uses 256.
	// This field is used only by type=dns.
	MaxConcurrentQueries int `json:"maxConcurrentQueries,omitempty"`
	// MaxTCPConnections bounds concurrently open DNS-over-TCP connections.
	// Zero uses 128. This field is used only by type=dns.
	MaxTCPConnections int `json:"maxTCPConnections,omitempty"`
	// MaxQueryBytes bounds a single UDP or TCP DNS request before parsing.
	// Zero uses 4096; valid explicit values are 512..65535.
	MaxQueryBytes int `json:"maxQueryBytes,omitempty"`
}
