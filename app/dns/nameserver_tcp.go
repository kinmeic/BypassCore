package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/url"
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
	clientIP        bcnet.IP
}

// NewTCPNameServer creates a DNS-over-TCP server using a plain TCP dialer.
func NewTCPNameServer(u *url.URL, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP bcnet.IP) (*TCPNameServer, error) {
	s, err := baseTCPNameServer(u, "TCP", disableCache, serveStale, serveExpiredTTL, clientIP)
	if err != nil {
		return nil, err
	}
	s.dial = func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, "tcp", s.destination.NetAddr())
	}
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
	}
	return s, nil
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
	errors.LogInfo(ctx, s.Name(), " querying DNS for: ", fqdn)

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

	conn, err := s.dial(dialCtx)
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to dial nameserver")
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	// 2-byte length prefix + message.
	if err := binary.Write(conn, binary.BigEndian, uint16(len(b))); err != nil {
		errors.LogErrorInner(ctx, err, "failed to write length")
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		return
	}
	if _, err := conn.Write(b); err != nil {
		errors.LogErrorInner(ctx, err, "failed to send query")
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		return
	}

	// Read 2-byte length prefix.
	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		errors.LogErrorInner(ctx, err, "failed to read response length")
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		return
	}
	respBuf := make([]byte, length)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		errors.LogErrorInner(ctx, err, "failed to read response body")
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		return
	}

	rec, err := parseResponse(respBuf)
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to parse DNS over TCP response")
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
