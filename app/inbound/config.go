// Package inbound implements the transparent proxy listener. It accepts TCP
// connections (redirected by iptables/nftables), recovers the original
// destination via SO_ORIGINAL_DST (redirect mode), and dispatches each
// connection to the router→outbound flow.
//
// This replaces xray-core's dokodemo-door inbound + app/proxyman/inbound/worker.
package inbound

// Config describes an inbound listener.
type Config struct {
	// Tag is the inbound identifier (e.g. "tcp_redir").
	Tag string `json:"tag"`
	// Type is the listener type: "tproxy" or "redirect".
	//   "redirect": iptables REDIRECT mode, uses SO_ORIGINAL_DST.
	//   "tproxy":   uses IP_TRANSPARENT and the socket's local address.
	Type string `json:"type"`
	// Listen is the bind address (e.g. "0.0.0.0").
	Listen string `json:"listen"`
	// Port is the listen port (e.g. 12345, the tproxy/redirect target).
	Port int `json:"port"`
	// Network is the protocol: "tcp", "udp", or "tcp,udp".
	// UDP is supported only with TPROXY/IP_TRANSPARENT.
	Network string `json:"network"`
	// Sniffing enables TLS/HTTP domain sniffing for routing while preserving
	// the kernel-provided destination used for the actual outbound connection.
	Sniffing bool `json:"sniffing"`
}
