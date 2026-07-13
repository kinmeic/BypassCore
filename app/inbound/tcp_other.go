//go:build !linux

package inbound

import "net"

func listenTCP(_ *Config, addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
