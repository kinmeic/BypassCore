//go:build linux

package inbound

import (
	"context"
	"net"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func listenTCP(cfg *Config, addr string) (net.Listener, error) {
	lc := net.ListenConfig{}
	if strings.EqualFold(cfg.Type, "tproxy") {
		lc.Control = func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
					sockErr = err
					return
				}
				_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
			}); err != nil {
				return err
			}
			return sockErr
		}
	}
	return lc.Listen(context.Background(), "tcp", addr)
}
