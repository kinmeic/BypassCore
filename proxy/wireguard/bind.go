package wireguard

import (
	"golang.zx2c4.com/wireguard/conn"
)

// reservedBind injects the reserved client identifier into bytes 1-3 of every
// outgoing packet. WARP-derived providers require it; vanilla WireGuard
// servers silently ignore non-zero reserved bytes.
type reservedBind struct {
	conn.Bind
	reserved [3]byte
}

// Send rewrites the reserved bytes of each packet before handing the batch to
// the underlying bind. Packets shorter than the 4-byte message header are
// left untouched.
func (b *reservedBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for i := range bufs {
		if len(bufs[i]) > 3 {
			bufs[i][1] = b.reserved[0]
			bufs[i][2] = b.reserved[1]
			bufs[i][3] = b.reserved[2]
		}
	}
	return b.Bind.Send(bufs, ep)
}
