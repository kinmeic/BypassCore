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

// sniffTimeout is the maximum time to wait for the first bytes of a
// connection. If the client sends nothing within this window (port scan,
// or a server-speaks-first protocol), we give up and route by IP:port.
const sniffTimeout = 4 * time.Second

// Sniff reads the first bytes of conn, recovers the sniffed domain, and
// returns a NEW net.Conn that replays the consumed bytes before reading
// from the underlying conn. The caller must use the returned conn for all
// subsequent I/O — the original conn has already been partially read.
//
// If sniffing is disabled or no domain is recovered, the returned conn is
// still the wrapped conn (so callers can always use the return value).
func (s *Sniffer) Sniff(conn net.Conn) (net.Conn, string) {
	if !s.enabled {
		return conn, ""
	}

	// Set a read deadline so a port-scan or server-speaks-first protocol
	// does not block the dispatch goroutine indefinitely.
	_ = conn.SetReadDeadline(time.Now().Add(sniffTimeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	// Clear the deadline regardless of outcome.
	_ = conn.SetReadDeadline(time.Time{})

	if err != nil || n == 0 {
		// If we read some bytes before an error (e.g. a partial read followed
		// by EOF), still wrap them so the caller sees the same stream.
		if n > 0 {
			return &prependConn{Conn: conn, buf: buf[:n]}, ""
		}
		return conn, ""
	}
	data := buf[:n]

	// Try TLS SNI first.
	if domain := tls.SniffSNI(data); domain != "" {
		return &prependConn{Conn: conn, buf: data}, domain
	}

	// Try HTTP Host.
	if domain := http.SniffHost(data); domain != "" {
		return &prependConn{Conn: conn, buf: data}, domain
	}

	// No domain recovered, but we consumed bytes — wrap them so the outbound
	// still receives the full stream.
	return &prependConn{Conn: conn, buf: data}, ""
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
