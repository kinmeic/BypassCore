package inbound

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"

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

	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a Listener.
func New(cfg *Config, d *dispatcher.Dispatcher) *Listener {
	return &Listener{cfg: cfg, dispatcher: d}
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

// Close stops all listeners.
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
			continue
		}
		l.wg.Add(1)
		go l.handleConn(conn)
	}
}

// handleConn recovers the original destination and dispatches.
func (l *Listener) handleConn(conn net.Conn) {
	defer l.wg.Done()

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
