package transport

import (
	"io"
	"net"
	"sync"
)

// ConnLink wraps a net.Conn into both sides of a Link. This is the simplest
// approach: the inbound connection's Read side becomes Link.Reader, its Write
// side becomes Link.Writer. The dispatcher bridges inbound.Conn ↔ outbound.Conn.
//
// For the dispatcher flow:
//   inboundConn → [Link.Reader] → outboundConn (client → remote)
//   outboundConn → [Link.Writer] ← inboundConn (remote → client)
//
// Bridge copies data bidirectionally between two net.Conns until either side
// closes.
func Bridge(a, b net.Conn) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	copyFn := func(dst net.Conn, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		// Close the write side of dst to signal EOF to the peer.
		if dc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = dc.CloseWrite()
		}
		errCh <- err
	}

	wg.Add(2)
	go copyFn(b, a) // a→b (client → remote)
	go copyFn(a, b) // b→a (remote → client)

	wg.Wait()
	close(errCh)
	// Return the first non-nil error (if any)
	for err := range errCh {
		if err != nil && err != io.EOF {
			return err
		}
	}
	return nil
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
