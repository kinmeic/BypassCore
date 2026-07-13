package inbound

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eugene/bypasscore/app/dispatcher"
	"github.com/eugene/bypasscore/common/errors"
)

// Listener is a transparent proxy listener supporting both TCP (redirect/tproxy)
// and UDP (tproxy). The network config field determines which protocols to listen on.
type Listener struct {
	cfg        *Config
	dispatcher *dispatcher.Dispatcher

	tcpListener net.Listener
	udpListener *udpTproxyListener
	wg          sync.WaitGroup

	// activeConns tracks accepted TCP connections so Close() can force-close
	// them, unblocking handleConn→Dispatch→Bridge goroutines that would
	// otherwise block wg.Wait() forever.
	connMu     sync.Mutex
	activeConns map[net.Conn]struct{}

	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a Listener.
func New(cfg *Config, d *dispatcher.Dispatcher) *Listener {
	return &Listener{
		cfg:        cfg,
		dispatcher: d,
		activeConns: make(map[net.Conn]struct{}),
	}
}

// Start begins listening on TCP and/or UDP based on the network config.
func (l *Listener) Start() error {
	l.ctx, l.cancel = context.WithCancel(context.Background())

	netCfg := strings.ToLower(l.cfg.Network)
	if netCfg == "" {
		netCfg = "tcp"
	}

	wantTCP := strings.Contains(netCfg, "tcp")
	wantUDP := strings.Contains(netCfg, "udp")

	if wantTCP {
		addr := net.JoinHostPort(l.cfg.Listen, strconv.Itoa(l.cfg.Port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return errors.New("inbound TCP listen failed: ", addr).Base(err)
		}
		l.tcpListener = ln
		errors.LogInfo(context.Background(), "inbound[", l.cfg.Tag, "] listening on tcp://", addr)
		l.wg.Add(1)
		go l.acceptLoop()
	}

	if wantUDP {
		udpLn, err := startUDP(l.cfg, l.dispatcher)
		if err != nil {
			// Close TCP listener if already started.
			if l.tcpListener != nil {
				l.tcpListener.Close()
			}
			return errors.New("inbound UDP listen failed").Base(err)
		}
		l.udpListener = udpLn
	}

	if !wantTCP && !wantUDP {
		return errors.New("inbound: network must be tcp, udp, or tcp,udp")
	}

	return nil
}

// Close stops all listeners and force-closes active connections so that
// blocked handleConn goroutines unblock and wg.Wait() returns promptly.
func (l *Listener) Close() error {
	if l.cancel != nil {
		l.cancel()
	}
	if l.tcpListener != nil {
		_ = l.tcpListener.Close()
	}
	if l.udpListener != nil {
		_ = l.udpListener.Close()
	}
	// Force-close all active connections so Dispatch→Bridge goroutines
	// unblock (io.Copy returns when a conn is closed).
	l.connMu.Lock()
	for conn := range l.activeConns {
		_ = conn.Close()
	}
	l.activeConns = nil // prevent further tracking
	l.connMu.Unlock()
	l.wg.Wait()
	return nil
}

// acceptLoop accepts TCP connections and dispatches them.
func (l *Listener) acceptLoop() {
	defer l.wg.Done()
	for {
		conn, err := l.tcpListener.Accept()
		if err != nil {
			if l.ctx.Err() != nil {
				return
			}
			errors.LogErrorInner(context.Background(), err, "inbound accept failed")
			// Back off on persistent errors (e.g. EMFILE) to avoid burning CPU.
			select {
			case <-l.ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		l.wg.Add(1)
		go l.handleConn(conn)
	}
}

// handleConn recovers the original destination and dispatches.
func (l *Listener) handleConn(conn net.Conn) {
	defer l.wg.Done()

	// Track the connection so Close() can force-close it to unblock Bridge.
	l.connMu.Lock()
	if l.activeConns != nil {
		l.activeConns[conn] = struct{}{}
		defer func() {
			l.connMu.Lock()
			delete(l.activeConns, conn)
			l.connMu.Unlock()
		}()
	}
	l.connMu.Unlock()

	// Get original destination via SO_ORIGINAL_DST (TCP redirect/tproxy).
	dest, err := getOriginalDst(conn)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "inbound failed to get original dest")
		conn.Close()
		return
	}

	// Dispatch blocks until the connection is fully proxied.
	if err := l.dispatcher.Dispatch(l.ctx, conn, dest); err != nil {
		errors.LogErrorInner(context.Background(), err, "inbound dispatch failed for ", dest.String())
	}
}
