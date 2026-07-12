package inbound

import (
	"context"
	"net"
	"strconv"
	"sync"

	"github.com/eugene/bypasscore/app/dispatcher"
	"github.com/eugene/bypasscore/common/errors"
)

// Listener is a TCP transparent proxy listener. It accepts connections,
// recovers the original destination, and dispatches them to the dispatcher.
type Listener struct {
	cfg        *Config
	dispatcher *dispatcher.Dispatcher

	tcpListener net.Listener
	wg          sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a Listener.
func New(cfg *Config, d *dispatcher.Dispatcher) *Listener {
	return &Listener{cfg: cfg, dispatcher: d}
}

// Start begins listening and accepting connections.
func (l *Listener) Start() error {
	l.ctx, l.cancel = context.WithCancel(context.Background())

	addr := net.JoinHostPort(l.cfg.Listen, strconv.Itoa(l.cfg.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return errors.New("inbound listen failed: ", addr).Base(err)
	}
	l.tcpListener = ln

	errors.LogInfo(context.Background(), "inbound[", l.cfg.Tag, "] listening on tcp://", addr)

	l.wg.Add(1)
	go l.acceptLoop()

	return nil
}

// Close stops the listener.
func (l *Listener) Close() error {
	if l.cancel != nil {
		l.cancel()
	}
	if l.tcpListener != nil {
		_ = l.tcpListener.Close()
	}
	l.wg.Wait()
	return nil
}

// acceptLoop accepts connections and dispatches them.
func (l *Listener) acceptLoop() {
	defer l.wg.Done()
	for {
		conn, err := l.tcpListener.Accept()
		if err != nil {
			if l.ctx.Err() != nil {
				return // shutting down
			}
			errors.LogErrorInner(context.Background(), err, "inbound accept failed")
			continue
		}
		l.wg.Add(1)
		go l.handleConn(conn)
	}
}

// handleConn recovers the original destination and dispatches.
func (l *Listener) handleConn(conn net.Conn) {
	defer l.wg.Done()

	// Get original destination via SO_ORIGINAL_DST.
	dest, err := getOriginalDst(conn)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "inbound failed to get original dest")
		conn.Close()
		return
	}

	// If sniffing is enabled, the dispatcher will sniff and possibly override
	// the destination address.
	d := l.dispatcher
	if l.cfg.Sniffing {
		d = l.dispatcher // dispatcher already has sniffer if configured
	}

	// Dispatch blocks until the connection is fully proxied.
	if err := d.Dispatch(l.ctx, conn, dest); err != nil {
		errors.LogErrorInner(context.Background(), err, "inbound dispatch failed for ", dest.String())
	}
}
