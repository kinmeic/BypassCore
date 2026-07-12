//go:build !linux

package inbound

import (
	"net"

	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
)

// getOriginalDst is a stub on non-Linux platforms. SO_ORIGINAL_DST is a
// Linux-only iptables feature. On other platforms, the original destination
// cannot be recovered, so transparent proxying is not available.
func getOriginalDst(conn net.Conn) (bcnet.Destination, error) {
	return bcnet.Destination{}, errors.New("SO_ORIGINAL_DST not supported on this platform")
}
