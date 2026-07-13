//go:build !linux

package freedom

import "syscall"

// makeBindControl is a no-op on non-Linux platforms (SO_BINDTODEVICE is
// Linux-specific). The localIP binding (LocalAddr) still works everywhere.
// On non-Linux, interface binding is silently skipped — callers that need
// it should run on Linux.
func makeBindControl(_ string) func(network, address string, c syscall.RawConn) error {
	return nil
}
