package inbound

import (
	"context"
	"encoding/binary"
	stderrors "errors"
	"io"
	"net"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/common/session"
	"github.com/eugene/bypasscore/transport"
)

const (
	socks5Version = 5

	socks5MethodNoAuth       = 0
	socks5MethodNotAvailable = 0xff

	socks5CommandConnect = 1

	socks5AddressIPv4   = 1
	socks5AddressDomain = 3
	socks5AddressIPv6   = 4

	socks5ReplySucceeded              = 0
	socks5ReplyGeneralFailure         = 1
	socks5ReplyConnectionNotAllowed   = 2
	socks5ReplyNetworkUnreachable     = 3
	socks5ReplyHostUnreachable        = 4
	socks5ReplyConnectionRefused      = 5
	socks5ReplyTTLExpired             = 6
	socks5ReplyCommandNotSupported    = 7
	socks5ReplyAddressTypeUnsupported = 8

	socks5HandshakeTimeout = 10 * time.Second
)

// handleSOCKS5Conn implements the no-authentication TCP CONNECT subset needed
// by a local Caddy forward_proxy upstream. The requested domain is passed to
// the router unchanged, so domain rules do not depend on payload sniffing.
func (l *Listener) handleSOCKS5Conn(client net.Conn) error {
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(socks5HandshakeTimeout)); err != nil {
		return errors.New("set SOCKS5 handshake deadline").Base(err)
	}
	if err := negotiateSOCKS5NoAuth(client); err != nil {
		return err
	}
	dest, reply, err := readSOCKS5ConnectRequest(client)
	if err != nil {
		_ = writeSOCKS5Reply(client, reply, nil)
		return err
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return errors.New("clear SOCKS5 handshake deadline").Base(err)
	}

	ctx := l.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Source: bcnet.DestinationFromAddr(client.RemoteAddr()),
		Local:  bcnet.DestinationFromAddr(client.LocalAddr()),
		Tag:    l.inboundTag(),
		Name:   "socks5",
	})
	ctx = session.ContextWithContent(ctx, new(session.Content))

	outbound, err := l.dispatcher.DialOutbound(ctx, dest)
	if err != nil {
		_ = writeSOCKS5Reply(client, socks5ReplyForError(err), nil)
		return errors.New("SOCKS5 outbound dial failed for ", dest.String()).Base(err)
	}
	defer outbound.Close()

	if err := writeSOCKS5Reply(client, socks5ReplySucceeded, outbound.LocalAddr()); err != nil {
		return errors.New("write SOCKS5 success reply").Base(err)
	}
	return transport.Bridge(client, outbound)
}

func negotiateSOCKS5NoAuth(conn net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return errors.New("read SOCKS5 greeting").Base(err)
	}
	if header[0] != socks5Version {
		return errors.New("unsupported SOCKS version: ", header[0])
	}
	if header[1] == 0 {
		return errors.New("SOCKS5 greeting contains no authentication methods")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return errors.New("read SOCKS5 authentication methods").Base(err)
	}
	selected := byte(socks5MethodNotAvailable)
	for _, method := range methods {
		if method == socks5MethodNoAuth {
			selected = socks5MethodNoAuth
			break
		}
	}
	if err := writeSOCKS5Bytes(conn, []byte{socks5Version, selected}); err != nil {
		return errors.New("write SOCKS5 method selection").Base(err)
	}
	if selected == socks5MethodNotAvailable {
		return errors.New("SOCKS5 client does not offer no-authentication")
	}
	return nil
}

func readSOCKS5ConnectRequest(conn net.Conn) (bcnet.Destination, byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return bcnet.Destination{}, socks5ReplyGeneralFailure, errors.New("read SOCKS5 request").Base(err)
	}
	if header[0] != socks5Version {
		return bcnet.Destination{}, socks5ReplyGeneralFailure, errors.New("invalid SOCKS5 request version: ", header[0])
	}
	if header[2] != 0 {
		return bcnet.Destination{}, socks5ReplyGeneralFailure, errors.New("invalid SOCKS5 reserved byte")
	}

	var address bcnet.Address
	switch header[3] {
	case socks5AddressIPv4:
		raw := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return bcnet.Destination{}, socks5ReplyGeneralFailure, errors.New("read SOCKS5 IPv4 address").Base(err)
		}
		address = bcnet.IPAddress(raw)
	case socks5AddressIPv6:
		raw := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return bcnet.Destination{}, socks5ReplyGeneralFailure, errors.New("read SOCKS5 IPv6 address").Base(err)
		}
		address = bcnet.IPAddress(raw)
	case socks5AddressDomain:
		var size [1]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return bcnet.Destination{}, socks5ReplyGeneralFailure, errors.New("read SOCKS5 domain length").Base(err)
		}
		if size[0] == 0 {
			return bcnet.Destination{}, socks5ReplyAddressTypeUnsupported, errors.New("SOCKS5 domain must not be empty")
		}
		raw := make([]byte, int(size[0]))
		if _, err := io.ReadFull(conn, raw); err != nil {
			return bcnet.Destination{}, socks5ReplyGeneralFailure, errors.New("read SOCKS5 domain").Base(err)
		}
		domain := string(raw)
		if !validSOCKS5Domain(domain) {
			return bcnet.Destination{}, socks5ReplyAddressTypeUnsupported, errors.New("invalid SOCKS5 domain")
		}
		address = bcnet.DomainAddress(domain)
	default:
		return bcnet.Destination{}, socks5ReplyAddressTypeUnsupported, errors.New("unsupported SOCKS5 address type: ", header[3])
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return bcnet.Destination{}, socks5ReplyGeneralFailure, errors.New("read SOCKS5 port").Base(err)
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		return bcnet.Destination{}, socks5ReplyGeneralFailure, errors.New("SOCKS5 destination port must not be zero")
	}
	if header[1] != socks5CommandConnect {
		return bcnet.Destination{}, socks5ReplyCommandNotSupported, errors.New("unsupported SOCKS5 command: ", header[1])
	}
	return bcnet.TCPDestination(address, bcnet.Port(port)), socks5ReplySucceeded, nil
}

func validSOCKS5Domain(domain string) bool {
	if domain == "" || !utf8.ValidString(domain) || strings.TrimSpace(domain) != domain ||
		strings.ContainsAny(domain, "\x00/:[]") {
		return false
	}
	return strings.IndexFunc(domain, func(value rune) bool {
		return unicode.IsControl(value) || unicode.IsSpace(value)
	}) < 0
}

func writeSOCKS5Reply(conn net.Conn, reply byte, bound net.Addr) error {
	addressType := byte(socks5AddressIPv4)
	address := []byte{0, 0, 0, 0}
	var port uint16
	if tcpAddr, ok := bound.(*net.TCPAddr); ok {
		port = uint16(tcpAddr.Port)
		if ip4 := tcpAddr.IP.To4(); ip4 != nil {
			address = append(address[:0], ip4...)
		} else if ip6 := tcpAddr.IP.To16(); ip6 != nil {
			addressType = socks5AddressIPv6
			address = append(address[:0], ip6...)
		}
	}
	response := make([]byte, 0, 4+len(address)+2)
	response = append(response, socks5Version, reply, 0, addressType)
	response = append(response, address...)
	response = binary.BigEndian.AppendUint16(response, port)
	return writeSOCKS5Bytes(conn, response)
}

func writeSOCKS5Bytes(conn net.Conn, value []byte) error {
	for len(value) > 0 {
		written, err := conn.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		value = value[written:]
	}
	return nil
}

func socks5ReplyForError(err error) byte {
	switch {
	case stderrors.Is(err, syscall.EACCES), stderrors.Is(err, syscall.EPERM):
		return socks5ReplyConnectionNotAllowed
	case stderrors.Is(err, syscall.ENETUNREACH):
		return socks5ReplyNetworkUnreachable
	case stderrors.Is(err, syscall.EHOSTUNREACH):
		return socks5ReplyHostUnreachable
	case stderrors.Is(err, syscall.ECONNREFUSED):
		return socks5ReplyConnectionRefused
	case stderrors.Is(err, context.DeadlineExceeded):
		return socks5ReplyTTLExpired
	default:
		return socks5ReplyGeneralFailure
	}
}
