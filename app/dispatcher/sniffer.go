package dispatcher

import (
	"net"

	"github.com/eugene/bypasscore/common/protocol/http"
	"github.com/eugene/bypasscore/common/protocol/tls"
)

// Sniffer reads the first bytes of a TCP connection to recover the domain
// (TLS SNI or HTTP Host) so that domain-based routing rules work for
// tproxy/redirect flows that arrive as IP:port.
type Sniffer struct {
	enabled bool
}

// NewSniffer creates a Sniffer. If enabled is false, Sniff returns "".
func NewSniffer(enabled bool) *Sniffer {
	return &Sniffer{enabled: enabled}
}

// Sniff reads the first bytes of conn and returns the sniffed domain, or ""
// if sniffing is disabled or no domain could be recovered. It uses a
// buffered reader so the consumed bytes are not lost — the returned conn
// is a pre-pended wrapper.
func (s *Sniffer) Sniff(conn net.Conn) string {
	if !s.enabled {
		return ""
	}

	// Read up to 4096 bytes (enough for TLS ClientHello or HTTP request line).
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	data := buf[:n]

	// Try TLS SNI first.
	if domain := tls.SniffSNI(data); domain != "" {
		return domain
	}

	// Try HTTP Host.
	if domain := http.SniffHost(data); domain != "" {
		return domain
	}

	return ""
}
