package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/common/log"
	bcnet "github.com/eugene/bypasscore/common/net"
	dns_feature "github.com/eugene/bypasscore/features/dns"
	"golang.org/x/net/http2"
)

// DoHNameServer implements DNS over HTTPS (RFC 8484) wire format using the
// standard library net/http client with crypto/tls. Its transport dialer can
// be replaced so remote DNS follows the normal routing/outbound policy.
type DoHNameServer struct {
	cacheController *CacheController
	httpClient      *http.Client
	dohURL          string
	clientIP        bcnet.IP
	destination     bcnet.Destination
	dial            Dialer
}

// NewDoHNameServer creates a DoH client. h2c selects HTTP/2 cleartext.
func NewDoHNameServer(u *url.URL, h2c bool, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP bcnet.IP) *DoHNameServer {
	u = cloneURL(u)
	mode := "DOH"
	port := bcnet.Port(443)
	if h2c {
		u.Scheme = "http"
		mode = "DOH-H2C"
		port = 80
	} else {
		u.Scheme = "https"
	}
	if u.Port() != "" {
		if parsed, err := bcnet.PortFromString(u.Port()); err == nil {
			port = parsed
		}
	}
	errors.LogInfo(context.Background(), "DNS: created ", mode, " client for ", u.String())
	s := &DoHNameServer{
		cacheController: NewCacheController(mode+"//"+u.Host, disableCache, serveStale, serveExpiredTTL),
		dohURL:          u.String(),
		clientIP:        clientIP,
		destination:     bcnet.TCPDestination(bcnet.ParseAddress(u.Hostname()), port),
	}
	s.dial = func(ctx context.Context, dest bcnet.Destination) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, "tcp", dest.NetAddr())
	}
	if h2c {
		s.httpClient = &http.Client{Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				return s.dial(ctx, s.destination)
			},
		}, Timeout: 8 * time.Second}
		return s
	}
	transport := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       bcnet.ConnIdleTimeout,
		ResponseHeaderTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			ServerName: u.Hostname(),
			MinVersion: tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return s.dial(ctx, s.destination)
		},
	}
	s.httpClient = &http.Client{Transport: transport, Timeout: 8 * time.Second}
	return s
}

func cloneURL(u *url.URL) *url.URL {
	copy := *u
	return &copy
}

func (s *DoHNameServer) SetDialer(dial Dialer) { s.dial = dial }

// Name implements Server.
func (s *DoHNameServer) Name() string { return s.cacheController.name }

// IsDisableCache implements Server.
func (s *DoHNameServer) IsDisableCache() bool { return s.cacheController.disableCache }

// DoH ignores reqID (server returns it in the response body).
func (s *DoHNameServer) newReqID() uint16 { return 0 }

// getCacheController implements CachedNameserver.
func (s *DoHNameServer) getCacheController() *CacheController { return s.cacheController }

// sendQuery implements CachedNameserver.
func (s *DoHNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogDebug(ctx, s.Name(), " querying: ", fqdn)

	// Random EDNS0 padding to obscure traffic patterns (RFC 8467 best effort).
	reqs, err := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, randBetween(100, 300)))
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
		go func(r *dnsRequest) {
			dnsCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()

			b, err := packMessage(r.msg)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to pack dns query for ", fqdn)
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			resp, err := s.dohHTTPSContext(dnsCtx, b)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to retrieve response for ", fqdn)
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			rec, err := parseResponseForRequest(resp, r)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to handle DOH response for ", fqdn)
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			if rec.RawHeader.Truncated {
				err := errors.New("truncated DOH response")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			log.Record(&log.DNSLog{Server: s.Name(), Domain: fqdn, Result: rec.IP, Status: log.DNSQueried})
			s.cacheController.updateRecord(r, rec)
		}(req)
	}
}

// dohHTTPSContext issues a RFC 8484 binary POST and returns the raw response body.
func (s *DoHNameServer) dohHTTPSContext(ctx context.Context, b []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", s.dohURL, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("User-Agent", "BypassCore")
	req.Header.Set("X-Padding", randomPadding(100, 1000))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("DOH server returned code %d", resp.StatusCode)
	}
	const maxDNSMessageSize = 65535
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessageSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDNSMessageSize {
		return nil, fmt.Errorf("DOH response exceeds %d bytes", maxDNSMessageSize)
	}
	return data, nil
}

func (s *DoHNameServer) Close() error {
	if transport, ok := s.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	if transport, ok := s.httpClient.Transport.(*http2.Transport); ok {
		transport.CloseIdleConnections()
	}
	return s.cacheController.Close()
}

// QueryIP implements Server.
func (s *DoHNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]bcnet.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}

// randBetween returns a random int in [lo, hi).
func randBetween(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	return lo + rand.Intn(hi-lo)
}

// randomPadding returns a base62-like random padding string of length in [lo, hi).
func randomPadding(lo, hi int) string {
	const letters = "0123123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	n := randBetween(lo, hi)
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
