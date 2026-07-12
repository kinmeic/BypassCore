package dns

import (
	"context"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/common/log"
	dns_feature "github.com/eugene/bypasscore/features/dns"
)

// localResolver is the minimal interface the LocalNameServer needs (the system
// resolver). It mirrors features/dns/localdns.Client but lives here so the DNS
// package is self-contained.
type localResolver interface {
	LookupIP(domain string, option dns_feature.IPOption) ([]bcnet.IP, uint32, error)
}

// systemResolver wraps the standard library resolver.
type systemResolver struct{}

func (systemResolver) LookupIP(domain string, option dns_feature.IPOption) ([]bcnet.IP, uint32, error) {
	ips, err := bcnet.LookupIP(domain)
	if err != nil {
		return nil, 0, err
	}
	out := make([]bcnet.IP, 0, len(ips))
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			if option.IPv4Enable {
				out = append(out, bcnet.IP(v4))
			}
		} else if option.IPv6Enable {
			out = append(out, bcnet.IP(ip.To16()))
		}
	}
	if len(out) == 0 {
		return nil, 0, dns_feature.ErrEmptyResponse
	}
	return out, dns_feature.DefaultTTL, nil
}

// LocalNameServer resolves via the system resolver. Cache is always disabled.
type LocalNameServer struct {
	client localResolver
}

// QueryIP implements Server.
func (s *LocalNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) (ips []bcnet.IP, ttl uint32, err error) {
	start := time.Now()
	ips, ttl, err = s.client.LookupIP(domain, option)
	if len(ips) > 0 {
		errors.LogInfo(ctx, "Localhost got answer: ", domain, " -> ", ips)
		log.Record(&log.DNSLog{Server: s.Name(), Domain: domain, Result: ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: err})
	}
	return
}

// Name implements Server.
func (s *LocalNameServer) Name() string { return "localhost" }

// IsDisableCache implements Server.
func (s *LocalNameServer) IsDisableCache() bool { return true }

// getCacheController is required by CachedNameserver but local lookups aren't
// cached; return nil so queryIP falls through to fetch().
func (s *LocalNameServer) getCacheController() *CacheController { return nil }

// sendQuery is required by CachedNameserver; local lookups are synchronous via
// QueryIP directly, so this is never called in practice.
func (s *LocalNameServer) sendQuery(_ context.Context, _ chan<- error, _ string, _ dns_feature.IPOption) {}

// NewLocalNameServer creates a local-resolver DNS server.
func NewLocalNameServer() *LocalNameServer {
	errors.LogInfo(context.Background(), "DNS: created localhost client")
	return &LocalNameServer{client: systemResolver{}}
}

// NewLocalDNSClient creates a Client wrapping a local-resolver server.
func NewLocalDNSClient(ipOption dns_feature.IPOption) *Client {
	return &Client{server: NewLocalNameServer(), ipOption: &ipOption}
}

// localClient adapts a LocalNameServer to the featdns.Client interface for use
// as a standalone resolver (e.g. when no dns config is provided).
type localClient struct {
	server *LocalNameServer
}

// NewLocal creates a minimal featdns.Client backed by the system resolver.
func NewLocal() dns_feature.Client {
	return &localClient{server: NewLocalNameServer()}
}

func (c *localClient) LookupIP(domain string, option dns_feature.IPOption) ([]bcnet.IP, uint32, error) {
	return c.server.QueryIP(context.Background(), domain, option)
}
func (c *localClient) Type() interface{} { return dns_feature.ClientType() }
func (c *localClient) Start() error     { return nil }
func (c *localClient) Close() error     { return nil }
