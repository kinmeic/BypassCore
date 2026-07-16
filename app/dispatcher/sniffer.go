package dispatcher

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"time"

	commonmetrics "github.com/eugene/bypasscore/common/metrics"
	"github.com/eugene/bypasscore/common/protocol/http"
	"github.com/eugene/bypasscore/common/protocol/quic"
	"github.com/eugene/bypasscore/common/protocol/tls"
)

// Sniffer reads the first bytes of a TCP connection to recover the domain
// (TLS SNI or HTTP Host) so that domain-based routing rules work for
// tproxy/redirect flows that arrive as IP:port.
type Sniffer struct {
	enabled  bool
	timeout  time.Duration
	maxBytes int
}

// SniffPacketMetadata inspects one or more consecutive UDP datagrams. QUIC
// Initial packets may split CRYPTO data, so callers can append packets while
// needMore is true, subject to their queue and time bounds.
func (s *Sniffer) SniffPacketMetadata(packets [][]byte) (domain, protocol string, needMore bool) {
	if s == nil || !s.enabled || len(packets) == 0 {
		return "", "", false
	}
	data := bytes.Join(packets, nil)
	if len(data) > s.maxBytes {
		data = data[:s.maxBytes]
	}
	domain, needMore = quic.SniffSNI(data)
	if domain != "" {
		commonmetrics.Inc("bypasscore_sniff_total", "network", "udp", "result", "success", "protocol", "quic")
		return domain, "quic", false
	}
	result := "failure"
	if needMore {
		result = "need_more"
	}
	commonmetrics.Inc("bypasscore_sniff_total", "network", "udp", "result", result, "protocol", "quic")
	return "", "", needMore
}

// NewSniffer creates a Sniffer. If enabled is false, Sniff returns "".
func NewSniffer(enabled bool) *Sniffer {
	return &Sniffer{enabled: enabled, timeout: defaultSniffTimeout, maxBytes: defaultMaxSniffBytes}
}

// NewSnifferWithOptions creates a validated configurable sniffer.
func NewSnifferWithOptions(enabled bool, timeoutMs, maxBytes int) (*Sniffer, error) {
	if timeoutMs == 0 {
		timeoutMs = int(defaultSniffTimeout / time.Millisecond)
	}
	if timeoutMs < 10 || timeoutMs > 10_000 {
		return nil, fmt.Errorf("sniffingTimeoutMs must be between 10 and 10000")
	}
	if maxBytes == 0 {
		maxBytes = defaultMaxSniffBytes
	}
	if maxBytes < 512 || maxBytes > 1024*1024 {
		return nil, fmt.Errorf("sniffingMaxBytes must be between 512 and 1048576")
	}
	return &Sniffer{enabled: enabled, timeout: time.Duration(timeoutMs) * time.Millisecond, maxBytes: maxBytes}, nil
}

// sniffTimeout is the maximum total time to wait for enough bytes of a
// connection. If the client sends nothing within this window (port scan,
// or a server-speaks-first protocol), we give up and route by IP:port.
const defaultSniffTimeout = 500 * time.Millisecond

const defaultMaxSniffBytes = 32 * 1024

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

	_ = conn.SetReadDeadline(time.Now().Add(s.timeout))
	defer conn.SetReadDeadline(time.Time{})

	data := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	failureResult := "failure"
	for len(data) < s.maxBytes {
		remaining := s.maxBytes - len(data)
		if remaining < len(tmp) {
			tmp = tmp[:remaining]
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			data = append(data, tmp[:n]...)
			if domain, _ := tls.SniffSNIWithStatus(data); domain != "" {
				commonmetrics.Inc("bypasscore_sniff_total", "network", "tcp", "result", "success", "protocol", "tls")
				return &prependConn{Conn: conn, buf: data}, domain, "tls"
			}
			if domain := http.SniffHost(data); domain != "" {
				commonmetrics.Inc("bypasscore_sniff_total", "network", "tcp", "result", "success", "protocol", "http")
				return &prependConn{Conn: conn, buf: data}, domain, "http"
			}
			if !sniffNeedsMore(data, s.maxBytes) {
				break
			}
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				failureResult = "timeout"
			}
			break
		}
	}
	commonmetrics.Inc("bypasscore_sniff_total", "network", "tcp", "result", failureResult, "protocol", "unknown")
	if len(data) == 0 {
		return conn, "", ""
	}
	return &prependConn{Conn: conn, buf: data}, "", ""
}

func sniffNeedsMore(data []byte, maxBytes int) bool {
	if len(data) == 0 {
		return true
	}
	if data[0] == 0x16 { // TLS handshake record
		_, needMore := tls.SniffSNIWithStatus(data)
		return needMore
	}
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "PATCH "}
	for _, method := range methods {
		prefixLen := len(data)
		if prefixLen > len(method) {
			prefixLen = len(method)
		}
		if bytes.EqualFold(data[:prefixLen], []byte(method[:prefixLen])) {
			return len(data) < maxBytes && !containsHeaderEnd(data)
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

// WriteTo preserves io.Copy's fast path while replaying the bytes consumed by
// the sniffer first. It also avoids hiding the underlying TCP connection's
// optimized transfer implementation behind this wrapper.
func (p *prependConn) WriteTo(w io.Writer) (int64, error) {
	var written int64
	for len(p.buf) > 0 {
		n, err := w.Write(p.buf)
		written += int64(n)
		p.buf = p.buf[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	n, err := io.Copy(w, p.Conn)
	return written + n, err
}

func (p *prependConn) CloseRead() error {
	if conn, ok := p.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return nil
}

func (p *prependConn) CloseWrite() error {
	if conn, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

// Ensure prependConn satisfies net.Conn.
var _ net.Conn = (*prependConn)(nil)

// io.Copy should also work (it uses Read).
var _ io.Reader = (*prependConn)(nil)
