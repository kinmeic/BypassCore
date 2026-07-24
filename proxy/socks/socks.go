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
	"sync"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
)

// Handler is a SOCKS5 client dialer.
type Handler struct {
	tag           string
	server        string // socks server address "host:port"
	username      string
	password      string
	timeout       time.Duration
	maxUDPPayload int
}

var socksUDPPacketPool = sync.Pool{New: func() any {
	buf := make([]byte, 65535)
	return &buf
}}

const (
	maxSOCKSUDPDatagram = 65507
	// RSV + FRAG + ATYP + max domain length + PORT.
	maxSOCKSUDPHeader  = 3 + 1 + 1 + 255 + 2
	maxSOCKSUDPPayload = maxSOCKSUDPDatagram - maxSOCKSUDPHeader
)

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// New creates a SOCKS5 client handler.
//
//	tag: outbound tag
//	server: socks server "host:port" (e.g. "127.0.0.1:1080")
//	username/password: optional SOCKS5 auth credentials (empty = no auth)
func New(tag, server, username, password string) *Handler {
	return &Handler{
		tag:           tag,
		server:        server,
		username:      username,
		password:      password,
		timeout:       10 * time.Second,
		maxUDPPayload: maxSOCKSUDPPayload,
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
	handler := New(tag, server, user, pass)
	if value, ok := numericSetting(settings, "udpMaxPacketBytes"); ok && value >= 512 && value <= maxSOCKSUDPPayload {
		handler.maxUDPPayload = value
	}
	return handler
}

func numericSetting(settings map[string]any, key string) (int, bool) {
	if settings == nil {
		return 0, false
	}
	switch value := settings[key].(type) {
	case int:
		return value, true
	case int64:
		return int(value), int64(int(value)) == value
	case float64:
		converted := int(value)
		return converted, float64(converted) == value
	default:
		return 0, false
	}
}

// Tag returns the outbound tag.
func (h *Handler) Tag() string { return h.tag }

// Dial connects to the SOCKS5 server, performs the handshake, and returns a
// tunnelled connection to dest.
func (h *Handler) Dial(ctx context.Context, dest bcnet.Destination) (net.Conn, error) {
	network := "tcp"
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

	if dest.Network == bcnet.Network_UDP {
		udpConn, err := h.udpAssociate(ctx, conn, dest)
		if err != nil {
			conn.Close()
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		return udpConn, nil
	}

	if err := h.handshake(conn, dest); err != nil {
		conn.Close()
		return nil, err
	}

	// Reset deadline — the caller (transport.Bridge) will manage I/O timeouts.
	_ = conn.SetDeadline(time.Time{})

	errors.LogDebug(ctx, "socks5[", h.tag, "] connected ", h.server, " → ", dest.NetAddr())
	return conn, nil
}

// handshake performs the SOCKS5 greeting + CONNECT request.
func (h *Handler) handshake(conn net.Conn, dest bcnet.Destination) error {
	if err := h.authenticate(conn); err != nil {
		return err
	}
	req, err := buildCommandRequest(0x01, dest)
	if err != nil {
		return err
	}
	if err := writeAll(conn, req); err != nil {
		return errors.New("socks5 connect write failed").Base(err)
	}
	_, err = readCommandResponse(conn)
	return err
}

func (h *Handler) authenticate(conn net.Conn) error {
	// --- Greeting ---
	// Version 5, offer methods: no-auth (0x00) and/or user/pass (0x02)
	methods := []byte{0x00} // no-auth
	if h.username != "" || h.password != "" {
		methods = []byte{0x02} // credentials make authentication mandatory
	}

	greeting := make([]byte, 0, 3+len(methods))
	greeting = append(greeting, 0x05, byte(len(methods)))
	greeting = append(greeting, methods...)

	if err := writeAll(conn, greeting); err != nil {
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
		if h.username != "" || h.password != "" {
			return errors.New("socks5: server selected unoffered no-auth method")
		}
	case 0x02: // username/password
		if err := h.doUserPassAuth(conn); err != nil {
			return err
		}
	case 0xFF: // no acceptable methods
		return errors.New("socks5: server rejected all authentication methods")
	default:
		return fmt.Errorf("socks5: server selected unsupported method %d", method)
	}

	return nil
}

func readCommandResponse(conn net.Conn) (string, error) {
	// Read response: VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(var) BND.PORT(2)
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", errors.New("socks5 command read failed").Base(err)
	}
	if header[0] != 0x05 {
		return "", fmt.Errorf("socks5: invalid version %d in command response", header[0])
	}
	if header[1] != 0x00 {
		return "", fmt.Errorf("socks5: command failed with reply code %d (%s)", header[1], replyCodeText(header[1]))
	}

	var host string
	switch header[3] {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", errors.New("socks5: failed to read BND.ADDR (IPv4)").Base(err)
		}
		host = net.IP(buf).String()
	case 0x03: // domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", errors.New("socks5: failed to read BND.ADDR length").Base(err)
		}
		buf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", errors.New("socks5: failed to read BND.ADDR (domain)").Base(err)
		}
		host = string(buf)
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", errors.New("socks5: failed to read BND.ADDR (IPv6)").Base(err)
		}
		host = net.IP(buf).String()
	default:
		return "", fmt.Errorf("socks5: unknown ATYP %d in command response", header[3])
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", errors.New("socks5: failed to read BND.PORT").Base(err)
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))), nil
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

	if err := writeAll(conn, req); err != nil {
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
	return buildCommandRequest(0x01, dest)
}

func buildCommandRequest(command byte, dest bcnet.Destination) ([]byte, error) {
	req := []byte{0x05, command, 0x00}

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

func (h *Handler) udpAssociate(ctx context.Context, control net.Conn, dest bcnet.Destination) (net.Conn, error) {
	if err := h.authenticate(control); err != nil {
		return nil, err
	}
	requestDest := bcnet.UDPDestination(bcnet.AnyIP, 0)
	req, err := buildCommandRequest(0x03, requestDest)
	if err != nil {
		return nil, err
	}
	if err := writeAll(control, req); err != nil {
		return nil, errors.New("socks5 UDP ASSOCIATE write failed").Base(err)
	}
	relay, err := readCommandResponse(control)
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(relay)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		serverHost, _, splitErr := net.SplitHostPort(h.server)
		if splitErr != nil {
			return nil, splitErr
		}
		relay = net.JoinHostPort(serverHost, port)
	}
	udpDialer := net.Dialer{Timeout: h.timeout}
	packetConn, err := udpDialer.DialContext(ctx, "udp", relay)
	if err != nil {
		return nil, errors.New("socks5 UDP relay dial failed").Base(err)
	}
	targetRequest, err := buildCommandRequest(0, dest)
	if err != nil {
		_ = packetConn.Close()
		return nil, err
	}
	header := append([]byte{0, 0, 0}, targetRequest[3:]...)
	return &udpAssociateConn{Conn: packetConn, control: control, target: dest, maxPayload: h.maxUDPPayload, header: header}, nil
}

type udpAssociateConn struct {
	net.Conn
	control    net.Conn
	target     bcnet.Destination
	maxPayload int
	header     []byte
}

func (c *udpAssociateConn) Write(payload []byte) (int, error) {
	maxPayload := c.maxPayload
	if maxPayload == 0 {
		maxPayload = maxSOCKSUDPPayload
	}
	if len(payload) > maxPayload {
		return 0, errors.New("socks5: UDP payload exceeds configured udpMaxPacketBytes")
	}
	header := c.header
	if len(header) == 0 {
		request, err := buildCommandRequest(0, c.target)
		if err != nil {
			return 0, err
		}
		header = append([]byte{0, 0, 0}, request[3:]...)
	}
	bufp := socksUDPPacketPool.Get().(*[]byte)
	storage := *bufp
	defer socksUDPPacketPool.Put(bufp)
	required := len(header) + len(payload)
	if required > maxSOCKSUDPDatagram || required > len(storage) {
		return 0, errors.New("socks5: UDP payload exceeds maximum datagram size")
	}
	packet := storage[:0]
	packet = append(packet, header...)
	packet = append(packet, payload...)
	n, err := c.Conn.Write(packet)
	if err != nil {
		return 0, err
	}
	if n != len(packet) {
		return 0, io.ErrShortWrite
	}
	return len(payload), nil
}

func (c *udpAssociateConn) Read(payload []byte) (int, error) {
	for {
		bufp := socksUDPPacketPool.Get().(*[]byte)
		packet := *bufp
		n, err := c.Conn.Read(packet)
		if err != nil {
			socksUDPPacketPool.Put(bufp)
			return 0, err
		}
		offset, source, err := parseSocksUDPHeader(packet[:n])
		if err != nil {
			socksUDPPacketPool.Put(bufp)
			return 0, err
		}
		if source.Port != c.target.Port || (!c.target.Address.Family().IsDomain() && source.Address.String() != c.target.Address.String()) {
			// A UDP relay can carry unrelated or stale datagrams. Discard them
			// without killing the association used by the expected target.
			socksUDPPacketPool.Put(bufp)
			continue
		}
		response := packet[offset:n]
		if c.maxPayload > 0 && len(response) > c.maxPayload {
			socksUDPPacketPool.Put(bufp)
			return 0, errors.New("socks5: UDP response exceeds configured udpMaxPacketBytes")
		}
		if len(response) > len(payload) {
			socksUDPPacketPool.Put(bufp)
			return 0, io.ErrShortBuffer
		}
		copied := copy(payload, response)
		socksUDPPacketPool.Put(bufp)
		return copied, nil
	}
}

func (c *udpAssociateConn) Close() error {
	if c.control != nil {
		_ = c.control.Close()
	}
	return c.Conn.Close()
}

func (c *udpAssociateConn) SetDeadline(t time.Time) error {
	if c.control != nil {
		_ = c.control.SetDeadline(t)
	}
	return c.Conn.SetDeadline(t)
}

func parseSocksUDPHeader(packet []byte) (int, bcnet.Destination, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return 0, bcnet.Destination{}, errors.New("socks5: malformed or fragmented UDP packet")
	}
	offset := 4
	var address bcnet.Address
	switch packet[3] {
	case 0x01:
		if len(packet) < offset+4 {
			return 0, bcnet.Destination{}, errors.New("socks5: truncated UDP IPv4 address")
		}
		address = bcnet.IPAddress(packet[offset : offset+4])
		offset += 4
	case 0x04:
		if len(packet) < offset+16 {
			return 0, bcnet.Destination{}, errors.New("socks5: truncated UDP IPv6 address")
		}
		address = bcnet.IPAddress(packet[offset : offset+16])
		offset += 16
	case 0x03:
		if len(packet) < 5 {
			return 0, bcnet.Destination{}, errors.New("socks5: truncated UDP domain")
		}
		length := int(packet[4])
		if len(packet) < offset+1+length {
			return 0, bcnet.Destination{}, errors.New("socks5: truncated UDP domain")
		}
		address = bcnet.DomainAddress(string(packet[offset+1 : offset+1+length]))
		offset += 1 + length
	default:
		return 0, bcnet.Destination{}, errors.New("socks5: invalid UDP address type")
	}
	if offset+2 > len(packet) {
		return 0, bcnet.Destination{}, errors.New("socks5: truncated UDP packet")
	}
	port := bcnet.Port(binary.BigEndian.Uint16(packet[offset : offset+2]))
	offset += 2
	return offset, bcnet.UDPDestination(address, port), nil
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
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}
