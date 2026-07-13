package dispatcher

import (
	"io"
	"net"
	"time"

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

// sniffTimeout is the maximum total time to wait for enough bytes of a
// connection. If the client sends nothing within this window (port scan,
// or a server-speaks-first protocol), we give up and route by IP:port.
const sniffTimeout = 500 * time.Millisecond

const maxSniffBytes = 32 * 1024

// Sniff reads the first bytes of conn, recovers the sniffed domain, and
// returns a NEW net.Conn that replays the consumed bytes before reading
// from the underlying conn. The caller must use the returned conn for all
// subsequent I/O — the original conn has already been partially read.
//
// If sniffing is disabled or no domain is recovered, the returned conn is
// still the wrapped conn (so callers can always use the return value).
func (s *Sniffer) Sniff(conn net.Conn) (net.Conn, string) {
	wrapped, domain, _ := s.SniffMetadata(conn)
	return wrapped, domain
}

// SniffMetadata incrementally reads a bounded prefix and returns the sniffed
// domain and protocol. Incremental reads prevent trivial TLS/HTTP segmentation
// from bypassing domain rules.
func (s *Sniffer) SniffMetadata(conn net.Conn) (net.Conn, string, string) {
	if !s.enabled {
		return conn, "", ""
	}

	_ = conn.SetReadDeadline(time.Now().Add(sniffTimeout))
	defer conn.SetReadDeadline(time.Time{})

	data := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for len(data) < maxSniffBytes {
		n, err := conn.Read(tmp)
		if n > 0 {
			data = append(data, tmp[:n]...)
			if domain := tls.SniffSNI(data); domain != "" {
				return &prependConn{Conn: conn, buf: data}, domain, "tls"
			}
			if domain := http.SniffHost(data); domain != "" {
				return &prependConn{Conn: conn, buf: data}, domain, "http"
			}
			if !sniffNeedsMore(data) {
				break
			}
		}
		if err != nil {
			break
		}
	}
	if len(data) == 0 {
		return conn, "", ""
	}
	return &prependConn{Conn: conn, buf: data}, "", ""
}

func sniffNeedsMore(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	if data[0] == 0x16 { // TLS handshake record
		if len(data) < 5 {
			return true
		}
		recordLen := int(data[3])<<8 | int(data[4])
		return len(data) < 5+recordLen
	}
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "PATCH "}
	for _, method := range methods {
		prefixLen := len(data)
		if prefixLen > len(method) {
			prefixLen = len(method)
		}
		if string(data[:prefixLen]) == method[:prefixLen] {
			return len(data) < maxSniffBytes && !containsHeaderEnd(data)
		}
	}
	return false
}

func containsHeaderEnd(data []byte) bool {
	for i := 0; i+3 < len(data); i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			return true
		}
	}
	return false
}

// prependConn wraps a net.Conn, replaying buffered bytes first on Read before
// reading from the underlying conn. This lets the Sniffer consume bytes for
// domain recovery without losing them — the outbound stream sees the complete
// client data.
type prependConn struct {
	net.Conn
	buf []byte // pre-read bytes to replay before reading from Conn
}

func (p *prependConn) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// Ensure prependConn satisfies net.Conn.
var _ net.Conn = (*prependConn)(nil)

// io.Copy should also work (it uses Read).
var _ io.Reader = (*prependConn)(nil)
