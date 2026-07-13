package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eugene/bypasscore/common"
	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	dns_feature "github.com/eugene/bypasscore/features/dns"

	"golang.org/x/net/dns/dnsmessage"
)

// ClassicNameServer implements traditional UDP DNS using the standard library
// net package. Each QueryIP dials a UDP socket, sends the query, and reads the
// response synchronously with a deadline. This replaces the original routed-UDP
// dispatcher which required the proxy forwarding stack.
type ClassicNameServer struct {
	sync.Mutex
	cacheController *CacheController
	address         bcnet.Destination
	clientIP        bcnet.IP
	reqID           uint32
}

// NewClassicNameServer creates a UDP DNS server.
func NewClassicNameServer(address bcnet.Destination, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP bcnet.IP) *ClassicNameServer {
	if address.Port == 0 {
		address.Port = bcnet.Port(53)
	}
	s := &ClassicNameServer{
		cacheController: NewCacheController(strings.ToUpper(address.String()), disableCache, serveStale, serveExpiredTTL),
		address:         address,
		clientIP:        clientIP,
	}
	errors.LogInfo(context.Background(), "DNS: created UDP client for ", address.NetAddr())
	return s
}

// Name implements Server.
func (s *ClassicNameServer) Name() string { return s.cacheController.name }

// IsDisableCache implements Server.
func (s *ClassicNameServer) IsDisableCache() bool { return s.cacheController.disableCache }

// getCacheController implements CachedNameserver.
func (s *ClassicNameServer) getCacheController() *CacheController { return s.cacheController }

func (s *ClassicNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

// packMessage serializes a dnsmessage.Message into bytes.
func packMessage(msg *dnsmessage.Message) ([]byte, error) {
	var b []byte
	var err error
	b, err = msg.AppendPack(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// sendQuery implements CachedNameserver. It sends A/AAAA queries and delivers
// responses to the noResponseErrCh / pubsub subscribers set up by doFetch.
func (s *ClassicNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
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

	for _, req := range reqs {
		go s.sendOneQuery(ctx, noResponseErrCh, req)
	}
}

// sendOneQuery sends a single DNS message over UDP and processes the response.
func (s *ClassicNameServer) sendOneQuery(ctx context.Context, noResponseErrCh chan<- error, req *dnsRequest) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(8 * time.Second)
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", s.address.NetAddr())
	if err != nil {
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		errors.LogErrorInner(ctx, err, s.Name(), " failed to dial UDP")
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	b, err := packMessage(req.msg)
	if err != nil {
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		errors.LogErrorInner(ctx, err, s.Name(), " failed to pack dns query")
		return
	}
	if _, err := conn.Write(b); err != nil {
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		errors.LogErrorInner(ctx, err, s.Name(), " failed to send dns query")
		return
	}

	respBuf := make([]byte, 1352) // 1352 accommodates EDNS0 1350 + 2-byte length headroom
	n, err := conn.Read(respBuf)
	if err != nil {
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		errors.LogErrorInner(ctx, err, s.Name(), " failed to read dns response")
		return
	}

	ipRec, err := parseResponse(respBuf[:n])
	if err != nil {
		errors.LogErrorInner(ctx, err, s.Name(), " failed to parse dns response")
		if noResponseErrCh != nil {
			noResponseErrCh <- err
		}
		return
	}

	// If truncated, retry with EDNS0 (request larger UDP payload size).
	if ipRec.RawHeader.Truncated && len(req.msg.Additionals) == 0 {
		opt := new(dnsmessage.Resource)
		common.Must(opt.Header.SetEDNS0(1350, 0xfe00, true))
		opt.Body = &dnsmessage.OPTResource{}
		newMsg := *req.msg
		newMsg.Additionals = append(newMsg.Additionals, *opt)
		newMsg.ID = s.newReqID()
		retryReq := *req
		retryReq.msg = &newMsg
		s.sendOneQuery(ctx, noResponseErrCh, &retryReq)
		return
	}

	s.cacheController.updateRecord(req, ipRec)
}

func (s *ClassicNameServer) Close() error { return s.cacheController.Close() }

// QueryIP implements Server.
func (s *ClassicNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]bcnet.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}
