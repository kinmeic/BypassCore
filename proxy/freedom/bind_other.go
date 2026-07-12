//go:build !linux

package freedom

import "net"

// bindInterface is a no-op on non-Linux platforms (SO_BINDTODEVICE is
// Linux-specific). The localIP binding (LocalAddr) still works everywhere.
func bindInterface(_ net.Conn, _ string) error { return nil }
