package dns

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	dns_feature "github.com/eugene/bypasscore/features/dns"
)

// DOTNameServer implements DNS over TLS (DoT, RFC 7858) using crypto/tls over a
// standard TCP connection. This is a BypassCore addition: the reference
// implementation only had plaintext TCP DNS.
type DOTNameServer struct {
	*TCPNameServer
}

// NewDOTNameServer creates a DNS-over-TLS server. The TLS connection is
// established with tls.Dial using the server hostname for verification.
func NewDOTNameServer(u *url.URL, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP bcnet.IP) (*DOTNameServer, error) {
	base, err := baseTCPNameServer(u, "DoT", disableCache, serveStale, serveExpiredTTL, clientIP)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "853"
	}
	base.destination.Port = bcnet.Port(853)
	if port != "853" {
		parsed, err := bcnet.PortFromString(port)
		if err != nil {
			return nil, err
		}
		base.destination.Port = parsed
	}
	base.dial = func(ctx context.Context) (net.Conn, error) {
		rawConn, err := base.dialRaw(ctx, base.destination)
		if err != nil {
			return nil, err
		}
		// Set the deadline on the raw TCP conn so the handshake is bounded.
		deadline, ok := ctx.Deadline()
		if !ok {
			deadline = time.Now().Add(5 * time.Second)
		}
		_ = rawConn.SetDeadline(deadline)
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		// Reset deadline; the caller sets its own.
		_ = rawConn.SetDeadline(time.Time{})
		return tlsConn, nil
	}
	errors.LogInfo(context.Background(), "DNS: created DoT client for ", u.String())
	return &DOTNameServer{TCPNameServer: base}, nil
}

// Name overrides to report DoT.
func (s *DOTNameServer) Name() string { return s.cacheController.name }

// QueryIP implements Server.
func (s *DOTNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]bcnet.IP, uint32, error) {
	return queryIP(ctx, s.TCPNameServer, domain, option)
}
