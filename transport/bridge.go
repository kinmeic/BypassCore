package transport

import (
	"errors"
	"io"
	"net"
	"time"
)

const bridgeDrainTimeout = 30 * time.Second

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
// closes.
func Bridge(a, b net.Conn) error {
	errCh := make(chan error, 2)

	copyFn := func(dst net.Conn, src net.Conn) {
		_, err := io.Copy(dst, src)
		// Close the write side of dst to signal EOF to the peer.
		if dc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = dc.CloseWrite()
		} else {
			// A connection without half-close support cannot signal EOF while
			// remaining writable. Fully close it so the peer copy cannot leak.
			_ = dst.Close()
		}
		errCh <- err
	}

	go copyFn(b, a) // a→b (client → remote)
	go copyFn(a, b) // b→a (remote → client)

	firstErr := <-errCh
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
		if !isBridgeCloseError(secondErr) {
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

func isBridgeCloseError(err error) bool {
	return err == nil || err == io.EOF || errors.Is(err, net.ErrClosed)
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
