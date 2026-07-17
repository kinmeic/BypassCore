package dns

import (
	"context"
	stderrors "errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/common/geodata"
	commonmetrics "github.com/eugene/bypasscore/common/metrics"
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/common/session"
	"github.com/eugene/bypasscore/common/utils"
	dns_feature "github.com/eugene/bypasscore/features/dns"
)

// Server is the interface implemented by each transport (UDP/TCP/DoT/DoH/local).
type Server interface {
	// Name of the server (for logging).
	Name() string
	// IsDisableCache reports whether caching is disabled for this server.
	IsDisableCache() bool
	// QueryIP sends IP queries to the configured server.
	QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]bcnet.IP, uint32, error)
}

// Dialer routes a DNS transport connection to its configured destination.
type Dialer func(context.Context, bcnet.Destination) (net.Conn, error)

// TaggedDialer optionally forces a DNS transport through a configured
// outbound. An empty tag preserves normal routing semantics.
type TaggedDialer func(context.Context, bcnet.Destination, string) (net.Conn, error)

type routedNameServer interface {
	SetDialer(Dialer)
}

type rawNameServer interface {
	QueryRaw(context.Context, []byte) ([]byte, error)
}

// Client wraps a Server with policy: expected/unexpected IP filters, timeout,
// query-strategy overrides, and fallback behavior.
type Client struct {
	server        Server
	skipFallback  bool
	expectedIPs   geodata.IPMatcher
	unexpectedIPs geodata.IPMatcher
	actPrior      bool
	actUnprior    bool
	tag           string
	timeout       time.Duration
	finalQuery    bool
	ipOption      *dns_feature.IPOption
	checkSystem   bool
	policyID      uint32
	localDirect   bool
	outboundTag   string
	metricTag     string
	observer      atomic.Pointer[resultObserver]
	statusMu      sync.RWMutex
	status        UpstreamStatus
}

type Result struct {
	Domain    string     `json:"domain"`
	IPs       []bcnet.IP `json:"-"`
	TTL       uint32     `json:"ttl"`
	ServerTag string     `json:"serverTag"`
	At        time.Time  `json:"at"`
}

type ResultObserver func(Result)
type resultObserver struct{ call ResultObserver }

type UpstreamStatus struct {
	ServerTag     string    `json:"serverTag"`
	Name          string    `json:"name"`
	LastSuccess   time.Time `json:"lastSuccess,omitempty"`
	LastFailure   time.Time `json:"lastFailure,omitempty"`
	LastLatencyMs int64     `json:"lastLatencyMs,omitempty"`
	LastError     string    `json:"lastError,omitempty"`
}

// NewServer creates a transport Server from a destination URL. It dispatches on
// the address scheme. Servers marked `+local` dial directly; other transports
// can be attached to the routing data plane through DNS.SetDialer.
func NewServer(dest bcnet.Destination, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP bcnet.IP) (Server, error) {
	if address := dest.Address; address.Family().IsDomain() {
		raw := address.Domain()
		raw = stripLocalScheme(raw)
		u, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		switch {
		case strings.EqualFold(u.String(), "localhost"):
			return NewLocalNameServer(), nil
		case strings.EqualFold(u.Scheme, "https"), strings.EqualFold(u.Scheme, "h2c"):
			return NewDoHNameServer(u, u.Scheme == "h2c", disableCache, serveStale, serveExpiredTTL, clientIP), nil
		case strings.EqualFold(u.Scheme, "tls"):
			return NewDOTNameServer(u, disableCache, serveStale, serveExpiredTTL, clientIP)
		case strings.EqualFold(u.Scheme, "tcp"):
			return NewTCPNameServer(u, disableCache, serveStale, serveExpiredTTL, clientIP)
		case strings.EqualFold(u.Scheme, "udp"):
			port := bcnet.Port(53)
			if u.Port() != "" {
				port, err = bcnet.PortFromString(u.Port())
				if err != nil {
					return nil, err
				}
			}
			if u.Hostname() == "" {
				return nil, errors.New("UDP nameserver has empty host")
			}
			return NewClassicNameServer(bcnet.UDPDestination(bcnet.ParseAddress(u.Hostname()), port), disableCache, serveStale, serveExpiredTTL, clientIP), nil
		}
	}
	if dest.Network == bcnet.Network_Unknown {
		dest.Network = bcnet.Network_UDP
	}
	if dest.Network == bcnet.Network_UDP {
		return NewClassicNameServer(dest, disableCache, serveStale, serveExpiredTTL, clientIP), nil
	}
	return nil, errors.New("No available name server could be created from ", dest).AtWarning()
}

// NewClient builds a Client around a configured NameServer. updateRules is a
// callback that receives whether the server is a local DNS (used by the caller
// to decide system-resolver fallback behavior).
func NewClient(
	ctx context.Context,
	ns *NameServer,
	clientIP bcnet.IP,
	disableCache bool, serveStale bool, serveExpiredTTL uint32,
	tag string,
	ipOption dns_feature.IPOption,
	updateRules func(bool),
) (*Client, error) {
	client := &Client{}

	server, err := NewServer(ns.Address.AsDestination(), disableCache, serveStale, serveExpiredTTL, clientIP)
	if err != nil {
		return nil, errors.New("failed to create nameserver").Base(err).AtWarning()
	}

	_, isLocalDNS := server.(*LocalNameServer)
	updateRules(isLocalDNS)

	// Expected IPs filter.
	var expectedMatcher geodata.IPMatcher
	if len(ns.ExpectedIp) > 0 {
		expectedMatcher, err = geodata.IPReg.BuildIPMatcher(ns.ExpectedIp)
		if err != nil {
			return nil, errors.New("failed to create expected ip matcher").Base(err).AtWarning()
		}
	}
	// Unexpected IPs filter.
	var unexpectedMatcher geodata.IPMatcher
	if len(ns.UnexpectedIp) > 0 {
		unexpectedMatcher, err = geodata.IPReg.BuildIPMatcher(ns.UnexpectedIp)
		if err != nil {
			return nil, errors.New("failed to create unexpected ip matcher").Base(err).AtWarning()
		}
	}

	if len(clientIP) > 0 {
		switch ns.Address.Address.GetAddress().(type) {
		case *bcnet.IPOrDomain_Domain:
			errors.LogInfo(ctx, "DNS: client ", ns.Address.Address.GetDomain(), " uses clientIP ", clientIP.String())
		case *bcnet.IPOrDomain_Ip:
			errors.LogInfo(ctx, "DNS: client ", bcnet.IP(ns.Address.Address.GetIp()), " uses clientIP ", clientIP.String())
		}
	}

	timeout := 4000 * time.Millisecond
	if ns.TimeoutMs > 0 {
		timeout = time.Duration(ns.TimeoutMs) * time.Millisecond
	}

	client.server = server
	client.localDirect = isLocalDNSAddress(ns.Address.AsDestination())
	client.outboundTag = ns.OutboundTag
	client.metricTag = ns.Tag
	if client.metricTag == "" {
		client.metricTag = "_default"
	}
	client.status = UpstreamStatus{ServerTag: client.metricTag, Name: server.Name()}
	client.skipFallback = ns.SkipFallback
	client.expectedIPs = expectedMatcher
	client.unexpectedIPs = unexpectedMatcher
	client.actPrior = ns.ActPrior
	client.actUnprior = ns.ActUnprior
	client.tag = tag
	client.timeout = timeout
	client.finalQuery = ns.FinalQuery
	client.ipOption = &ipOption
	client.checkSystem = ns.QueryStrategy == QueryStrategy_USE_SYS
	client.policyID = ns.PolicyID
	return client, nil
}

// Name returns the server name the client manages.
func (c *Client) Name() string { return c.server.Name() }

// QueryIP sends a DNS query to the underlying server, applying query-strategy
// and expected/unexpected IP filtering.
func (c *Client) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]bcnet.IP, uint32, error) {
	started := time.Now()
	if c.checkSystem {
		supportIPv4, supportIPv6 := utils.CheckRoutes()
		option.IPv4Enable = option.IPv4Enable && supportIPv4
		option.IPv6Enable = option.IPv6Enable && supportIPv6
	} else {
		option.IPv4Enable = option.IPv4Enable && c.ipOption.IPv4Enable
		option.IPv6Enable = option.IPv6Enable && c.ipOption.IPv6Enable
	}

	if !option.IPv4Enable && !option.IPv6Enable {
		return nil, 0, dns_feature.ErrEmptyResponse
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: c.tag})
	ctx = session.ContextWithContent(ctx, &session.Content{Protocol: "dns", SkipDNSResolve: true})
	ips, ttl, err := c.server.QueryIP(ctx, domain, option)
	cancel()
	c.recordQuery(started, err)

	if err != nil {
		return nil, 0, err
	}
	if len(ips) == 0 {
		return nil, 0, dns_feature.ErrEmptyResponse
	}

	if c.expectedIPs != nil && !c.actPrior {
		ips, _ = c.expectedIPs.FilterIPs(ips)
		errors.LogDebug(context.Background(), "domain ", domain, " expectedIPs ", ips, " matched at server ", c.Name())
		if len(ips) == 0 {
			return nil, 0, dns_feature.ErrEmptyResponse
		}
	}
	if c.unexpectedIPs != nil && !c.actUnprior {
		_, ips = c.unexpectedIPs.FilterIPs(ips)
		errors.LogDebug(context.Background(), "domain ", domain, " unexpectedIPs ", ips, " matched at server ", c.Name())
		if len(ips) == 0 {
			return nil, 0, dns_feature.ErrEmptyResponse
		}
	}
	if c.expectedIPs != nil && c.actPrior {
		ipsNew, _ := c.expectedIPs.FilterIPs(ips)
		if len(ipsNew) > 0 {
			ips = ipsNew
			errors.LogDebug(context.Background(), "domain ", domain, " priorIPs ", ips, " matched at server ", c.Name())
		}
	}
	if c.unexpectedIPs != nil && c.actUnprior {
		_, ipsNew := c.unexpectedIPs.FilterIPs(ips)
		if len(ipsNew) > 0 {
			ips = ipsNew
			errors.LogDebug(context.Background(), "domain ", domain, " unpriorIPs ", ips, " matched at server ", c.Name())
		}
	}
	return ips, ttl, nil
}

func (c *Client) notifySelectedResult(domain string, ips []bcnet.IP, ttl uint32) {
	if observer := c.observer.Load(); observer != nil {
		observer.call(Result{Domain: domain, IPs: append([]bcnet.IP(nil), ips...), TTL: ttl, ServerTag: c.metricTag, At: time.Now()})
	}
}

// QueryRaw forwards one complete DNS wire message through the same tagged
// routing context as QueryIP. Record-type-agnostic forwarding deliberately
// bypasses the IP cache and expected-IP filters, which only apply to A/AAAA.
func (c *Client) QueryRaw(ctx context.Context, query []byte) ([]byte, error) {
	server, ok := c.server.(rawNameServer)
	if !ok {
		return nil, errors.New("DNS server ", c.Name(), " does not support raw queries")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: c.tag})
	ctx = session.ContextWithContent(ctx, &session.Content{Protocol: "dns", SkipDNSResolve: true})
	started := time.Now()
	response, err := server.QueryRaw(ctx, query)
	c.recordQuery(started, err)
	return response, err
}

func (c *Client) recordQuery(started time.Time, err error) {
	latency := time.Since(started)
	result := "success"
	if err != nil {
		result = "error"
		if netErr, ok := err.(net.Error); (ok && netErr.Timeout()) || stderrors.Is(err, context.DeadlineExceeded) {
			result = "timeout"
		}
	}
	commonmetrics.Inc("bypasscore_dns_upstream_queries_total", "server", c.metricTag, "result", result)
	commonmetrics.Add("bypasscore_dns_upstream_latency_nanoseconds_total", latency.Nanoseconds(), "server", c.metricTag)
	now := time.Now()
	c.statusMu.Lock()
	c.status.LastLatencyMs = latency.Milliseconds()
	if err == nil {
		c.status.LastSuccess = now
		c.status.LastError = ""
	} else {
		c.status.LastFailure = now
		c.status.LastError = err.Error()
	}
	c.statusMu.Unlock()
}

func (c *Client) upstreamStatus() UpstreamStatus {
	c.statusMu.RLock()
	defer c.statusMu.RUnlock()
	return c.status
}

func isLocalDNSAddress(dest bcnet.Destination) bool {
	if !dest.Address.Family().IsDomain() {
		return false
	}
	raw := strings.ToLower(dest.Address.Domain())
	if raw == "localhost" {
		return true
	}
	separator := strings.Index(raw, "://")
	return separator > 0 && strings.HasSuffix(raw[:separator], "+local")
}

func stripLocalScheme(raw string) string {
	separator := strings.Index(raw, "://")
	if separator <= 0 || !strings.HasSuffix(strings.ToLower(raw[:separator]), "+local") {
		return raw
	}
	return raw[:separator-len("+local")] + raw[separator:]
}

// ResolveIpOptionOverride applies a query strategy to narrow an IPOption.
func ResolveIpOptionOverride(queryStrategy QueryStrategy, ipOption dns_feature.IPOption) dns_feature.IPOption {
	switch queryStrategy {
	case QueryStrategy_USE_IP, QueryStrategy_USE_SYS:
		return ipOption
	case QueryStrategy_USE_IP4:
		return dns_feature.IPOption{IPv4Enable: ipOption.IPv4Enable, IPv6Enable: false, FakeEnable: false}
	case QueryStrategy_USE_IP6:
		return dns_feature.IPOption{IPv4Enable: false, IPv6Enable: ipOption.IPv6Enable, FakeEnable: false}
	default:
		return ipOption
	}
}
