//go:build !linux

package inbound

import (
	"errors"

	"github.com/eugene/bypasscore/app/dispatcher"
)

// startUDP is a stub on non-Linux platforms. UDP TPROXY requires
// IP_TRANSPARENT + IP_RECVORIGDSTADDR which are Linux-only socket options.
func startUDP(cfg *Config, d *dispatcher.Dispatcher) (*udpTproxyListener, error) {
	return nil, errors.New("UDP tproxy not supported on this platform")
}

type udpTproxyListener struct{}

func (*udpTproxyListener) setLimits(udpResourceLimits) {}
func (*udpTproxyListener) setTag(string)               {}

func (l *udpTproxyListener) Close() error { return nil }
