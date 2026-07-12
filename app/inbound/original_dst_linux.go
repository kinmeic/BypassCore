//go:build linux

package inbound

import (
	"net"
	"syscall"
	"unsafe"

	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
)

// SO_ORIGINAL_DST is the socket option to retrieve the original destination
// of a connection redirected by iptables REDIRECT or TPROXY.
const soOriginalDst = 80 // SO_ORIGINAL_DST

// getOriginalDst retrieves the original destination address from a redirected
// TCP connection using SO_ORIGINAL_DST.
func getOriginalDst(conn net.Conn) (bcnet.Destination, error) {
	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		return bcnet.Destination{}, errors.New("connection does not support syscall.Conn")
	}
	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		return bcnet.Destination{}, errors.New("failed to get raw conn").Base(err)
	}

	var dest bcnet.Destination
	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		// Try IPv4 first, then IPv6.
		level := syscall.IPPROTO_IP
		// The sockaddr_in6 structure is large enough for both IPv4 and IPv6.
		addr, err := syscall.GetsockoptIPv6MTUInfo(int(fd), level, soOriginalDst)
		if err != nil {
			// Try IPv6 level.
			level = syscall.IPPROTO_IPV6
			addr, err = syscall.GetsockoptIPv6MTUInfo(int(fd), level, soOriginalDst)
			if err != nil {
				sockErr = err
				return
			}
		}

		// Extract IP and port from the sockaddr.
		var ip net.IP
		if level == syscall.IPPROTO_IP {
			// IPv4: first 4 bytes of the flowinfo field.
			ip = (*[4]byte)(unsafe.Pointer(&addr.Addr.Flowinfo))[:]
		} else {
			// IPv6: the Addr field.
			ip = addr.Addr.Addr[:]
		}

		port := (*[2]byte)(unsafe.Pointer(&addr.Addr.Port))[:]
		p := bcnet.PortFromBytes(port)

		dest = bcnet.TCPDestination(bcnet.IPAddress(ip), p)
	})
	if err != nil {
		return bcnet.Destination{}, errors.New("failed to control fd").Base(err)
	}
	if sockErr != nil {
		return bcnet.Destination{}, errors.New("SO_ORIGINAL_DST failed").Base(sockErr)
	}
	return dest, nil
}
