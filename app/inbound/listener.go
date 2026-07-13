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
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/common/session"
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
	connMu      sync.Mutex
	activeConns map[net.Conn]struct{}

	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a Listener.
func New(cfg *Config, d *dispatcher.Dispatcher) *Listener {
	return &Listener{
		cfg:         cfg,
		dispatcher:  d,
		activeConns: make(map[net.Conn]struct{}),
	}
}

// Start begins listening on TCP and/or UDP based on the network config.
func (l *Listener) Start() error {
	l.ctx, l.cancel = context.WithCancel(context.Background())
	typeCfg := strings.ToLower(strings.TrimSpace(l.cfg.Type))
	if typeCfg == "" {
		typeCfg = "redirect"
	}
	if typeCfg != "redirect" && typeCfg != "tproxy" {
		return errors.New("inbound: type must be redirect or tproxy")
	}

	if l.cfg.Port < 1 || l.cfg.Port > 65535 {
		return errors.New("inbound: port must be between 1 and 65535")
	}
	wantTCP, wantUDP, err := parseInboundNetworks(l.cfg.Network)
	if err != nil {
		return err
	}
	if wantUDP && typeCfg != "tproxy" {
		return errors.New("inbound: UDP requires type=tproxy")
	}

	if wantTCP {
		addr := net.JoinHostPort(l.cfg.Listen, strconv.Itoa(l.cfg.Port))
		ln, err := listenTCP(l.cfg, addr)
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

func parseInboundNetworks(value string) (bool, bool, error) {
	if strings.TrimSpace(value) == "" {
		return true, false, nil
	}
	var tcp, udp bool
	for _, item := range strings.Split(strings.ToLower(value), ",") {
		switch strings.TrimSpace(item) {
		case "tcp":
			tcp = true
		case "udp":
			udp = true
		default:
			return false, false, errors.New("inbound: network must contain only tcp and/or udp")
		}
	}
	return tcp, udp, nil
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

	var dest bcnet.Destination
	var err error
	if strings.EqualFold(l.cfg.Type, "tproxy") {
		// As in Xray, a transparent TCP socket exposes the intercepted target as
		// the accepted connection's local address.
		dest = bcnet.DestinationFromAddr(conn.LocalAddr())
	} else {
		dest, err = getOriginalDst(conn)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "inbound failed to get original dest")
			conn.Close()
			return
		}
	}

	ctx := session.ContextWithInbound(l.ctx, &session.Inbound{
		Source: bcnet.DestinationFromAddr(conn.RemoteAddr()),
		Local:  bcnet.DestinationFromAddr(conn.LocalAddr()),
		Tag:    l.cfg.Tag,
	})
	ctx = session.ContextWithContent(ctx, new(session.Content))

	// Dispatch blocks until the connection is fully proxied.
	if err := l.dispatcher.Dispatch(ctx, conn, dest); err != nil {
		errors.LogErrorInner(context.Background(), err, "inbound dispatch failed for ", dest.String())
	}
}
