package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	dns_feature "github.com/eugene/bypasscore/features/dns"
)

// TCPNameServer implements DNS over TCP (RFC 7766) using the standard library.
type TCPNameServer struct {
	cacheController *CacheController
	destination     bcnet.Destination
	reqID           uint32
	dial            func(ctx context.Context) (net.Conn, error)
	rawDial         Dialer
	rawDialMu       sync.RWMutex
	clientIP        bcnet.IP
	idleConns       chan net.Conn
	closed          atomic.Bool
}

const defaultDNSMaxIdleTCPConnections = 4

// NewTCPNameServer creates a DNS-over-TCP server using a plain TCP dialer.
func NewTCPNameServer(u *url.URL, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP bcnet.IP) (*TCPNameServer, error) {
	s, err := baseTCPNameServer(u, "TCP", disableCache, serveStale, serveExpiredTTL, clientIP)
	if err != nil {
		return nil, err
	}
	s.dial = func(ctx context.Context) (net.Conn, error) { return s.dialRaw(ctx, s.destination) }
	errors.LogInfo(context.Background(), "DNS: created TCP client for ", u.String())
	return s, nil
}

func baseTCPNameServer(u *url.URL, prefix string, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP bcnet.IP) (*TCPNameServer, error) {
	port := bcnet.Port(53)
	if u.Port() != "" {
		var err error
		if port, err = bcnet.PortFromString(u.Port()); err != nil {
			return nil, err
		}
	}
	dest := bcnet.TCPDestination(bcnet.ParseAddress(u.Hostname()), port)
	s := &TCPNameServer{
		cacheController: NewCacheController(prefix+"//"+dest.NetAddr(), disableCache, serveStale, serveExpiredTTL),
		destination:     dest,
		clientIP:        clientIP,
		idleConns:       make(chan net.Conn, defaultDNSMaxIdleTCPConnections),
		rawDial: func(ctx context.Context, dest bcnet.Destination) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "tcp", dest.NetAddr())
		},
	}
	return s, nil
}

func (s *TCPNameServer) SetDialer(dial Dialer) {
	if dial == nil {
		return
	}
	s.rawDialMu.Lock()
	s.rawDial = dial
	s.rawDialMu.Unlock()
	s.closeIdleConnections()
}

func (s *TCPNameServer) dialRaw(ctx context.Context, destination bcnet.Destination) (net.Conn, error) {
	s.rawDialMu.RLock()
	dial := s.rawDial
	s.rawDialMu.RUnlock()
	return dial(ctx, destination)
}

// Name implements Server.
func (s *TCPNameServer) Name() string { return s.cacheController.name }

// IsDisableCache implements Server.
func (s *TCPNameServer) IsDisableCache() bool { return s.cacheController.disableCache }

// getCacheController implements CachedNameserver.
func (s *TCPNameServer) getCacheController() *CacheController { return s.cacheController }

func (s *TCPNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

// sendQuery implements CachedNameserver.
func (s *TCPNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogDebug(ctx, s.Name(), " querying DNS for: ", fqdn)

	reqs, err := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, 0))
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to build dns query for ", fqdn)
		if noResponseErrCh != nil {
			if option.IPv4Enable {
				noResponseErrCh <- err
			}
			if option.IPv6Enable {
				noResponseErrCh <- err
			}
		}
		return
	}

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(5 * time.Second)
	}

	for _, req := range reqs {
		go s.sendOneTCPQuery(ctx, noResponseErrCh, req, deadline)
	}
}

// sendOneTCPQuery sends a single query and reads the response over a TCP stream.
// Shared by TCP and DoT (DoT overrides the dial function).
func (s *TCPNameServer) sendOneTCPQuery(ctx context.Context, noResponseErrCh chan<- error, req *dnsRequest, deadline time.Time) {
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	b, err := packMessage(req.msg)
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to pack dns query")
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		return
	}

	var rec *IPRecord
	_, err = s.exchangeTCP(dialCtx, b, func(response []byte) error {
		var parseErr error
		rec, parseErr = parseResponseForRequest(response, req)
		return parseErr
	})
	if err != nil {
		errors.LogErrorInner(ctx, err, "DNS over TCP exchange failed")
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		return
	}

	if rec == nil {
		err := errors.New("DNS over TCP response validation produced no record")
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		return
	}
	if rec.RawHeader.Truncated {
		err := errors.New("truncated DNS response over TCP")
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		return
	}
	s.cacheController.updateRecord(req, rec)
}

// QueryIP implements Server.
func (s *TCPNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]bcnet.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}

// QueryRaw forwards an arbitrary DNS message over TCP or, for an embedded
// DOTNameServer, over the TLS-wrapped dial function.
func (s *TCPNameServer) QueryRaw(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) == 0 || len(query) > 65535 {
		return nil, errors.New("invalid raw DNS query length")
	}
	return s.exchangeTCP(ctx, query, func(response []byte) error {
		return dns_feature.ValidateRawResponse(query, response)
	})
}

// exchangeRawTCP remains available for the UDP truncation fallback, which has
// no owning TCPNameServer pool.
func exchangeRawTCP(ctx context.Context, query []byte, dial func(context.Context) (net.Conn, error)) ([]byte, error) {
	if len(query) == 0 || len(query) > 65535 {
		return nil, errors.New("invalid raw DNS query length")
	}
	conn, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	_ = conn.SetDeadline(deadline)
	if err := binary.Write(conn, binary.BigEndian, uint16(len(query))); err != nil {
		return nil, err
	}
	if err := writeDNSPayload(conn, query); err != nil {
		return nil, err
	}
	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, errors.New("empty DNS over TCP response")
	}
	response := make([]byte, int(length))
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *TCPNameServer) exchangeTCP(ctx context.Context, query []byte, validate func([]byte) error) ([]byte, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	for attempt := 0; attempt < 2; attempt++ {
		conn, reused, err := s.acquireTCP(ctx)
		if err != nil {
			return nil, err
		}
		_ = conn.SetDeadline(deadline)
		response, err := exchangeDNSMessage(conn, query)
		if err == nil && validate != nil {
			err = validate(response)
		}
		if err == nil {
			s.releaseTCP(conn, true)
			return response, nil
		}
		s.releaseTCP(conn, false)
		if !reused || ctx.Err() != nil {
			return nil, err
		}
		// An idle peer may close a pooled connection without notification. Retry
		// once on a fresh connection; never loop on a newly-created connection.
	}
	return nil, errors.New("DNS over TCP exchange failed")
}

func exchangeDNSMessage(conn net.Conn, query []byte) ([]byte, error) {
	if err := binary.Write(conn, binary.BigEndian, uint16(len(query))); err != nil {
		return nil, err
	}
	if err := writeDNSPayload(conn, query); err != nil {
		return nil, err
	}
	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, errors.New("empty DNS over TCP response")
	}
	response := make([]byte, int(length))
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *TCPNameServer) acquireTCP(ctx context.Context) (net.Conn, bool, error) {
	if s.closed.Load() {
		return nil, false, net.ErrClosed
	}
	select {
	case conn := <-s.idleConns:
		return conn, true, nil
	default:
	}
	conn, err := s.dial(ctx)
	return conn, false, err
}

func (s *TCPNameServer) releaseTCP(conn net.Conn, healthy bool) {
	if conn == nil {
		return
	}
	if !healthy || s.closed.Load() {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	select {
	case s.idleConns <- conn:
	default:
		_ = conn.Close()
	}
}

func (s *TCPNameServer) closeIdleConnections() {
	for {
		select {
		case conn := <-s.idleConns:
			_ = conn.Close()
		default:
			return
		}
	}
}

func writeDNSPayload(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		payload = payload[n:]
	}
	return nil
}

func (s *TCPNameServer) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.closeIdleConnections()
	return s.cacheController.Close()
}
