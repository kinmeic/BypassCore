//go:build linux

package freedom

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// makeBindControl returns a net.Dialer.Control function that sets
// SO_BINDTODEVICE on the socket BEFORE connect. This ensures the kernel
// selects the correct egress interface for the route.
func makeBindControl(iface string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var bindErr error
		err := c.Control(func(fd uintptr) {
			bindErr = syscall.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		})
		if err != nil {
			return err
		}
		return bindErr
	}
}
