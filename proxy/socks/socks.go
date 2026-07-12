// Package socks implements a SOCKS5 client dialer. It connects to a local
// (or remote) SOCKS5 server, performs the handshake (with optional
// username/password authentication), requests a CONNECT to the destination,
// and returns the established net.Conn for bidirectional copying.
//
// This replaces xray-core's proxy/socks outbound. In passwall2's architecture,
// the SOCKS5 server is typically naiveproxy or sing-box running on
// 127.0.0.1:<port>; BypassCore dials to it and forwards traffic, exactly as
// xray's `protocol: "socks"` outbound does.
package socks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
)

// Handler is a SOCKS5 client dialer.
type Handler struct {
	tag      string
	server   string // socks server address "host:port"
	username string
	password string
	timeout  time.Duration
}

// New creates a SOCKS5 client handler.
//   tag: outbound tag
//   server: socks server "host:port" (e.g. "127.0.0.1:1080")
//   username/password: optional SOCKS5 auth credentials (empty = no auth)
func New(tag, server, username, password string) *Handler {
	return &Handler{
		tag:      tag,
		server:   server,
		username: username,
		password: password,
		timeout:  10 * time.Second,
	}
}

// NewFromSettings creates a SOCKS5 handler from upstream config fields.
func NewFromSettings(tag, server string, settings map[string]any) *Handler {
	user := ""
	pass := ""
	if settings != nil {
		if u, ok := settings["username"].(string); ok {
			user = u
		}
		if p, ok := settings["password"].(string); ok {
			pass = p
		}
	}
	return New(tag, server, user, pass)
}

// Tag returns the outbound tag.
func (h *Handler) Tag() string { return h.tag }

// Dial connects to the SOCKS5 server, performs the handshake, and returns a
// tunnelled connection to dest.
func (h *Handler) Dial(ctx context.Context, dest bcnet.Destination) (net.Conn, error) {
	network := "tcp"
	if dest.Network == bcnet.Network_UDP {
		// SOCKS5 UDP associate is more complex; fall back to TCP for now.
		network = "tcp"
	}

	d := net.Dialer{Timeout: h.timeout}
	conn, err := d.DialContext(ctx, network, h.server)
	if err != nil {
		return nil, errors.New("socks5 connect to ", h.server, " failed").Base(err)
	}

	// Set deadline for the handshake phase.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(h.timeout)
	}
	_ = conn.SetDeadline(deadline)

	if err := h.handshake(conn, dest); err != nil {
		conn.Close()
		return nil, err
	}

	// Reset deadline — the caller (transport.Bridge) will manage I/O timeouts.
	_ = conn.SetDeadline(time.Time{})

	errors.LogInfo(ctx, "socks5[", h.tag, "] connected ", h.server, " → ", dest.NetAddr())
	return conn, nil
}

// handshake performs the SOCKS5 greeting + CONNECT request.
func (h *Handler) handshake(conn net.Conn, dest bcnet.Destination) error {
	// --- Greeting ---
	// Version 5, offer methods: no-auth (0x00) and/or user/pass (0x02)
	methods := []byte{0x00} // no-auth
	if h.username != "" || h.password != "" {
		methods = append(methods, 0x02) // username/password
	}

	greeting := make([]byte, 0, 3+len(methods))
	greeting = append(greeting, 0x05, byte(len(methods)))
	greeting = append(greeting, methods...)

	if _, err := conn.Write(greeting); err != nil {
		return errors.New("socks5 greeting write failed").Base(err)
	}

	// Read server's method selection: VER(1) METHOD(1)
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return errors.New("socks5 greeting read failed").Base(err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("socks5: invalid version %d in greeting response", resp[0])
	}
	method := resp[1]

	// --- Authentication (if required) ---
	switch method {
	case 0x00: // no auth
	case 0x02: // username/password
		if err := h.doUserPassAuth(conn); err != nil {
			return err
		}
	case 0xFF: // no acceptable methods
		return errors.New("socks5: server rejected all authentication methods")
	default:
		return fmt.Errorf("socks5: server selected unsupported method %d", method)
	}

	// --- CONNECT request ---
	req, err := buildConnectRequest(dest)
	if err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return errors.New("socks5 connect write failed").Base(err)
	}

	// Read response: VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(var) BND.PORT(2)
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return errors.New("socks5 connect read failed").Base(err)
	}
	if header[0] != 0x05 {
		return fmt.Errorf("socks5: invalid version %d in connect response", header[0])
	}
	if header[1] != 0x00 {
		return fmt.Errorf("socks5: CONNECT failed with reply code %d (%s)", header[1], replyCodeText(header[1]))
	}

	// Skip BND.ADDR + BND.PORT based on ATYP
	switch header[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, make([]byte, 4+2)); err != nil {
			return errors.New("socks5: failed to read BND.ADDR (IPv4)").Base(err)
		}
	case 0x03: // domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return errors.New("socks5: failed to read BND.ADDR length").Base(err)
		}
		if _, err := io.ReadFull(conn, make([]byte, int(lenBuf[0])+2)); err != nil {
			return errors.New("socks5: failed to read BND.ADDR (domain)").Base(err)
		}
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, make([]byte, 16+2)); err != nil {
			return errors.New("socks5: failed to read BND.ADDR (IPv6)").Base(err)
		}
	default:
		return fmt.Errorf("socks5: unknown ATYP %d in connect response", header[3])
	}

	return nil
}

// doUserPassAuth performs RFC 1929 username/password authentication.
func (h *Handler) doUserPassAuth(conn net.Conn) error {
	// Version 1 (sub-negotiation version), ULEN, UNAME, PLEN, PASSWD
	user := []byte(h.username)
	pass := []byte(h.password)
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("socks5: username/password too long (max 255)")
	}

	req := make([]byte, 0, 3+len(user)+len(pass))
	req = append(req, 0x01, byte(len(user)))
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)

	if _, err := conn.Write(req); err != nil {
		return errors.New("socks5: user/pass write failed").Base(err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return errors.New("socks5: user/pass read failed").Base(err)
	}
	if resp[0] != 0x01 {
		return fmt.Errorf("socks5: invalid auth version %d", resp[0])
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5: authentication failed (status %d)", resp[1])
	}
	return nil
}

// buildConnectRequest constructs the SOCKS5 CONNECT request for the given dest.
func buildConnectRequest(dest bcnet.Destination) ([]byte, error) {
	req := []byte{0x05, 0x01, 0x00} // VER, CMD=CONNECT, RSV=0

	addr := dest.Address
	host := ""
	port := int(dest.Port)

	if addr.Family().IsDomain() {
		host = addr.Domain()
		if len(host) > 255 {
			return nil, errors.New("socks5: domain too long (max 255)")
		}
		req = append(req, 0x03) // ATYP=domain
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	} else {
		ip := addr.IP()
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01) // ATYP=IPv4
			req = append(req, v4...)
		} else {
			ip6 := ip.To16()
			if ip6 == nil {
				return nil, errors.New("socks5: invalid destination IP")
			}
			req = append(req, 0x04) // ATYP=IPv6
			req = append(req, ip6...)
		}
	}

	// Port (big-endian 2 bytes)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	return req, nil
}

// replyCodeText maps SOCKS5 reply codes to human-readable text.
func replyCodeText(code byte) string {
	switch code {
	case 0x00:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown error"
	}
}

// ParseServer splits "host:port" or "host" into host and port.
func ParseServer(server string) (host string, port int) {
	if h, p, err := net.SplitHostPort(server); err == nil {
		return h, parsePort(p)
	}
	// No port — default 1080
	return server, 1080
}

func parsePort(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n > 65535 {
		return 1080
	}
	return n
}
