//go:build linux

package freedom

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// bindInterface binds the connection to the given network interface using
// SO_BINDTODEVICE. This is Linux-only.
func bindInterface(conn net.Conn, iface string) error {
	rawConn, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return nil // not a raw-capable connection (e.g. tls.Conn), skip
	}
	rc, err := rawConn.SyscallConn()
	if err != nil {
		return err
	}
	var bindErr error
	err = rc.Control(func(fd uintptr) {
		bindErr = syscall.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
	})
	if err != nil {
		return err
	}
	return bindErr
}
