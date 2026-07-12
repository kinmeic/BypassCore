// Package transport defines the Link type connecting inbound and outbound
// handlers. A Link is simply a pair of io.ReadCloser / io.WriteCloser that
// the dispatcher uses to bridge an accepted connection to a dialed outbound.
package transport

import "io"

// Link connects an inbound reader/writer to an outbound reader/writer.
// Reader provides data flowing from the inbound connection (client → server).
// Writer accepts data flowing toward the inbound connection (server → client).
type Link struct {
	Reader io.ReadWriteCloser
	Writer io.ReadWriteCloser
}
