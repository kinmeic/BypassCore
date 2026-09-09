package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	bridgeDrainTimeout = 30 * time.Second
	bridgeBufferSize   = 32 * 1024

	// DefaultConnIdleTimeout bounds how long an established tunnel may carry no
	// traffic in either direction before Bridge closes it. It mirrors Xray's
	// connIdle policy default of 300 seconds.
	DefaultConnIdleTimeout = 300 * time.Second
)

// connIdleTimeoutKey carries a per-connection idle timeout override through
// the dispatch context.
type connIdleTimeoutKey struct{}

// ContextWithConnIdleTimeout attaches the TCP idle timeout that Bridge applies
// to the connection dispatched with this context.
func ContextWithConnIdleTimeout(ctx context.Context, timeout time.Duration) context.Context {
	return context.WithValue(ctx, connIdleTimeoutKey{}, timeout)
}

// ConnIdleTimeoutFromContext returns the configured idle timeout, or
// DefaultConnIdleTimeout when the context carries none.
func ConnIdleTimeoutFromContext(ctx context.Context) time.Duration {
	if ctx == nil {
		return DefaultConnIdleTimeout
	}
	if timeout, ok := ctx.Value(connIdleTimeoutKey{}).(time.Duration); ok {
		return timeout
	}
	return DefaultConnIdleTimeout
}

// ConnLink wraps a net.Conn into both sides of a Link. This is the simplest
// approach: the inbound connection's Read side becomes Link.Reader, its Write
// side becomes Link.Writer. The dispatcher bridges inbound.Conn ↔ outbound.Conn.
//
// For the dispatcher flow:
//
//	inboundConn → [Link.Reader] → outboundConn (client → remote)
//	outboundConn → [Link.Writer] ← inboundConn (remote → client)
//
// Bridge copies data bidirectionally between two net.Conns until either side
// closes or the connection stays idle for DefaultConnIdleTimeout.
func Bridge(a, b net.Conn) error {
	return BridgeWithIdleTimeout(a, b, DefaultConnIdleTimeout)
}

// BridgeWithIdleTimeout copies data bidirectionally between two net.Conns
// until either side closes. When both directions stay silent for idleTimeout
// the bridge closes both sides, so peers that hold idle tunnels open
// indefinitely (for example a fronting reverse proxy's keep-alive pool)
// cannot pin the bridge goroutines and buffers forever. Traffic in either
// direction counts as activity. A non-positive idleTimeout disables the
// eviction and restores pure io.Copy semantics.
func BridgeWithIdleTimeout(a, b net.Conn, idleTimeout time.Duration) error {
	errCh := make(chan error, 2)
	guard := newIdleGuard(a, b, idleTimeout)

	copyFn := func(dst net.Conn, src net.Conn) {
		err := copyWithIdleTimeout(dst, src, guard)
		// Close the write side of dst to signal EOF to the peer.
		if dc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = dc.CloseWrite()
		}
		// If dst cannot half-close, leave it open while the reverse direction
		// drains. The bridge-wide timeout below still bounds peers that wait for
		// EOF, without truncating a final response already in flight.
		errCh <- err
	}

	go copyFn(b, a) // a→b (client → remote)
	go copyFn(a, b) // b→a (remote → client)

	firstErr := <-errCh
	if isIdleTimeoutError(firstErr) {
		// Idle eviction is a normal lifecycle event, not a failure. Close both
		// sides immediately instead of draining: the peer already proved it has
		// nothing to send.
		_ = a.Close()
		_ = b.Close()
		<-errCh
		return nil
	}
	if !isBridgeCloseError(firstErr) {
		// A fatal error cannot be recovered by draining the other direction.
		// Closing both sides also guarantees that the second io.Copy exits.
		_ = a.Close()
		_ = b.Close()
		<-errCh
		return firstErr
	}

	// Preserve TCP half-close semantics after a clean EOF so a peer can still
	// send its final response. Bound the drain period so a peer that never
	// closes cannot retain the bridge and its goroutines forever.
	timer := time.NewTimer(bridgeDrainTimeout)
	defer timer.Stop()
	select {
	case secondErr := <-errCh:
		if !isBridgeCloseError(secondErr) && !isIdleTimeoutError(secondErr) {
			return secondErr
		}
		return nil
	case <-timer.C:
		_ = a.Close()
		_ = b.Close()
		<-errCh
		return nil
	}
}

// copyWithIdleTimeout copies src→dst. With an active guard it refreshes the
// shared session deadline on every read; without one it is a plain io.Copy.
func copyWithIdleTimeout(dst, src net.Conn, guard *idleGuard) error {
	if guard == nil {
		_, err := io.Copy(dst, src)
		return err
	}
	buf := make([]byte, bridgeBufferSize)
	guard.ping()
	for {
		n, err := src.Read(buf)
		if n > 0 {
			guard.ping()
			if writeErr := writeFully(dst, buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			return err
		}
	}
}

// idleGuard applies a session-level idle timeout across both bridge
// directions: traffic in either direction extends the read deadline of both
// conns, so a one-way stream (e.g. a long download) is not evicted while it
// is still making progress. Only when both directions stay silent for the
// full timeout do the pending reads expire and the bridge close.
type idleGuard struct {
	timeout  time.Duration
	a, b     net.Conn
	mu       sync.Mutex
	deadline time.Time
}

func newIdleGuard(a, b net.Conn, timeout time.Duration) *idleGuard {
	if timeout <= 0 {
		return nil
	}
	return &idleGuard{timeout: timeout, a: a, b: b}
}

// ping records activity and pushes out both conns' read deadlines. To avoid
// per-read timer churn on busy tunnels, extensions are skipped while more
// than half of the previous runway remains.
func (g *idleGuard) ping() {
	now := time.Now()
	g.mu.Lock()
	if now.Add(g.timeout/2).Before(g.deadline) {
		g.mu.Unlock()
		return
	}
	g.deadline = now.Add(g.timeout)
	deadline := g.deadline
	g.mu.Unlock()
	_ = g.a.SetReadDeadline(deadline)
	_ = g.b.SetReadDeadline(deadline)
}

func writeFully(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func isBridgeCloseError(err error) bool {
	return err == nil || err == io.EOF || errors.Is(err, net.ErrClosed)
}

func isIdleTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// NewConnLink creates a Link from a single net.Conn. This is used when the
// inbound already has a net.Conn and the dispatcher needs a Link to pass to
// the outbound handler.
//
// For our simplified data plane, we don't actually use Link's Reader/Writer
// as separate pipe endpoints. Instead, the dispatcher holds the inbound
// net.Conn directly and passes it to the outbound handler. Link is kept for
// interface compatibility.
func NewConnLink(conn net.Conn) *Link {
	return &Link{
		Reader: &connRWC{conn},
		Writer: &connRWC{conn},
	}
}

// connRWC wraps a net.Conn to satisfy io.ReadWriteCloser.
type connRWC struct {
	net.Conn
}

func (c *connRWC) Close() error { return c.Conn.Close() }
