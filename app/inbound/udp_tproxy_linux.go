//go:build linux

// Package inbound implements transparent proxy listeners.
// This file implements UDP TPROXY using IP_TRANSPARENT + IP_RECVORIGDSTADDR.
//
// UDP TPROXY flow:
//  1. iptables TPROXY redirects UDP packets to this listener's port
//  2. We create a socket with IP_TRANSPARENT + IP_RECVORIGDSTADDR
//  3. ReadMsgUDP returns payload + OOB control message containing the
//     original destination (IP_RECVORIGDSTADDR)
//  4. We route by original dest, dial the outbound, and relay packets
//  5. Return packets are written back with the original dest as source
//     (IP_TRANSPARENT allows binding to non-local addresses)
package inbound

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/eugene/bypasscore/app/dispatcher"
	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/common/session"
	"golang.org/x/sys/unix"
)

// udpTproxyListener is a UDP TPROXY listener.
type udpTproxyListener struct {
	cfg        *Config
	dispatcher *dispatcher.Dispatcher

	conn     *net.UDPConn
	sessions sync.Map // key: "srcAddr|originalDst" → *udpSession
	createMu sync.Mutex
	count    atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// udpSession represents one client's UDP relay: the outbound connection +
// a goroutine copying return packets back to the client.
type udpSession struct {
	key         string
	clientAddr  *net.UDPAddr      // client source address
	originalDst bcnet.Destination // original target (from TPROXY)
	outbound    net.Conn          // outbound connection (to proxy/freedom)
	replyConn   net.PacketConn    // transparent socket bound to originalDst
	listener    *udpTproxyListener
	ctx         context.Context
	cancel      context.CancelFunc
	packets     chan []byte
	queuedBytes atomic.Int64

	mu        sync.Mutex
	closeOnce sync.Once
	closed    chan struct{}
}

const (
	udpSessionIdleTimeout = 2 * time.Minute
	// Bound both per-flow memory and the number of sockets/goroutines an
	// untrusted UDP source can create. A single maximum-size datagram still
	// fits, while bursts overflow instead of growing memory without bound.
	udpSessionQueueBytes = 64 * 1024
	udpSessionQueueSlots = 64
	udpMaxSessions       = 1024
	udpSniffWait         = 25 * time.Millisecond
	udpSniffMaxPackets   = 4
)

// startUDP creates a UDP TPROXY listener.
func startUDP(cfg *Config, d *dispatcher.Dispatcher) (*udpTproxyListener, error) {
	addr := net.JoinHostPort(cfg.Listen, strconv.Itoa(cfg.Port))

	// Create a raw UDP socket with IP_TRANSPARENT + IP_RECVORIGDSTADDR.
	// We can't use net.ListenUDP because it doesn't set these socket options
	// before bind. We need to set them on the socket fd before binding.
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				// SO_REUSEADDR + SO_REUSEPORT
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					sockErr = err
					return
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					sockErr = err
					return
				}
				// IP_TRANSPARENT — allows binding to non-local addresses (for spoofing src in replies)
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
					sockErr = err
					return
				}
				// IP_RECVORIGDSTADDR — receive the original destination in OOB data
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
					sockErr = err
					return
				}
				// For IPv6
				_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
				_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}

	network := "udp"
	if ip := net.ParseIP(strings.Trim(cfg.Listen, "[]")); ip != nil {
		if ip.To4() != nil {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, errors.New("UDP tproxy listen failed: ", addr).Base(err)
	}

	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, errors.New("expected *net.UDPConn")
	}

	l := &udpTproxyListener{
		cfg:        cfg,
		dispatcher: d,
		conn:       udpConn,
	}
	l.ctx, l.cancel = context.WithCancel(context.Background())

	errors.LogInfo(context.Background(), "inbound[", cfg.Tag, "] listening on udp://", addr)

	l.wg.Add(1)
	go l.recvLoop()

	return l, nil
}

// recvLoop reads UDP packets with OOB data, extracts the original destination,
// and relays each packet to the outbound.
func (l *udpTproxyListener) recvLoop() {
	defer l.wg.Done()

	buf := make([]byte, 65535)
	oob := make([]byte, 1024)

	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}

		n, oobN, _, srcAddr, err := l.conn.ReadMsgUDP(buf, oob)
		if err != nil {
			if l.ctx.Err() != nil {
				return
			}
			errors.LogErrorInner(context.Background(), err, "UDP tproxy read failed")
			continue
		}

		// Extract original destination from OOB control message.
		origDst := retrieveOriginalDst(oob[:oobN])
		if !origDst.IsValid() {
			errors.LogDebug(context.Background(), "UDP tproxy: no original dest in OOB, dropping")
			continue
		}

		// Match Xray's non-cone UDP key: the same client socket may talk to
		// multiple destinations and those flows must not share one outbound.
		key := srcAddr.String() + "|" + origDst.String()
		s := l.getOrCreateSession(key, srcAddr, origDst)
		if s == nil {
			errors.LogWarning(context.Background(), "UDP relay session limit reached, dropping packet")
			continue
		}
		s.enqueue(buf[:n])
	}
}

func (l *udpTproxyListener) getOrCreateSession(key string, src *net.UDPAddr, dst bcnet.Destination) *udpSession {
	if value, ok := l.sessions.Load(key); ok {
		return value.(*udpSession)
	}

	l.createMu.Lock()
	defer l.createMu.Unlock()
	if value, ok := l.sessions.Load(key); ok {
		return value.(*udpSession)
	}
	if l.ctx.Err() != nil || l.count.Load() >= udpMaxSessions {
		return nil
	}
	ctx, cancel := context.WithCancel(l.ctx)
	s := &udpSession{
		key:         key,
		clientAddr:  src,
		originalDst: dst,
		listener:    l,
		ctx:         ctx,
		cancel:      cancel,
		packets:     make(chan []byte, udpSessionQueueSlots),
		closed:      make(chan struct{}),
	}
	l.sessions.Store(key, s)
	l.count.Add(1)
	l.wg.Add(1)
	go s.run()
	return s
}

// retrieveOriginalDest parses the IP_RECVORIGDSTADDR control message from OOB data.
func retrieveOriginalDst(oob []byte) bcnet.Destination {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return bcnet.Destination{}
	}
	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
			// data layout: [2 bytes port BE][2 bytes unused/pad][4 bytes IP]
			if len(msg.Data) >= 8 {
				port := bcnet.PortFromBytes(msg.Data[2:4])
				ip := bcnet.IPAddress(msg.Data[4:8])
				return bcnet.UDPDestination(ip, port)
			}
		} else if msg.Header.Level == syscall.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			// data layout: [2 bytes port BE][2 bytes unused][4 bytes flowinfo][16 bytes IP]
			if len(msg.Data) >= 24 {
				port := bcnet.PortFromBytes(msg.Data[2:4])
				ip := bcnet.IPAddress(msg.Data[8:24])
				return bcnet.UDPDestination(ip, port)
			}
		}
	}
	return bcnet.Destination{}
}

func (s *udpSession) enqueue(data []byte) {
	size := int64(len(data))
	for {
		queued := s.queuedBytes.Load()
		if queued+size > udpSessionQueueBytes {
			errors.LogWarning(context.Background(), "UDP relay byte queue full for ", s.key, ", dropping packet")
			return
		}
		if s.queuedBytes.CompareAndSwap(queued, queued+size) {
			break
		}
	}
	packet := append([]byte(nil), data...)
	select {
	case <-s.closed:
		s.queuedBytes.Add(-size)
	case s.packets <- packet:
	default:
		s.queuedBytes.Add(-size)
		errors.LogWarning(context.Background(), "UDP relay queue full for ", s.key, ", dropping packet")
	}
}

type udpReadResult struct {
	data []byte
	err  error
}

// run serializes dialing, packet writes and return delivery for one flow. This
// removes the per-packet goroutine/data race and gives the session an idle TTL.
func (s *udpSession) run() {
	defer s.listener.wg.Done()
	defer s.close()

	// Route using the first datagram. QUIC CRYPTO data can cross Initial
	// packets; collect only when the sniffer explicitly requests more data and
	// keep the wait tightly bounded for latency-sensitive UDP protocols.
	var pending [][]byte
	select {
	case <-s.ctx.Done():
		return
	case packet := <-s.packets:
		s.queuedBytes.Add(-int64(len(packet)))
		pending = append(pending, packet)
	}
collectLoop:
	for len(pending) < udpSniffMaxPackets {
		_, _, needMore := s.listener.dispatcher.SniffPacketMetadata(pending)
		if !needMore {
			break
		}
		timer := time.NewTimer(udpSniffWait)
		select {
		case packet := <-s.packets:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			s.queuedBytes.Add(-int64(len(packet)))
			pending = append(pending, packet)
		case <-timer.C:
			break collectLoop
		case <-s.ctx.Done():
			timer.Stop()
			return
		}
		if len(pending) == 0 || len(pending) >= udpSniffMaxPackets {
			break
		}
	}

	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	conn, err := s.listener.dispatcher.DialOutboundPackets(s.routingContext(ctx), s.originalDst, pending)
	cancel()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "UDP relay: outbound dial failed for ", s.originalDst.String())
		return
	}
	replyConn, err := listenTransparentReply(s.originalDst)
	if err != nil {
		conn.Close()
		errors.LogErrorInner(context.Background(), err, "UDP relay: failed to create transparent reply socket")
		return
	}
	if !s.setResources(conn, replyConn) {
		return
	}
	for _, packet := range pending {
		if _, err := conn.Write(packet); err != nil {
			errors.LogErrorInner(context.Background(), err, "UDP relay: initial write to outbound failed")
			return
		}
	}

	reads := make(chan udpReadResult, 1)
	go s.readUDPResponses(conn, reads)
	timer := time.NewTimer(udpSessionIdleTimeout)
	defer timer.Stop()
	resetTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(udpSessionIdleTimeout)
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-timer.C:
			return
		case packet := <-s.packets:
			s.queuedBytes.Add(-int64(len(packet)))
			resetTimer()
			if _, err := conn.Write(packet); err != nil {
				errors.LogErrorInner(context.Background(), err, "UDP relay: write to outbound failed")
				return
			}
		case result := <-reads:
			if result.err != nil {
				return
			}
			resetTimer()
			if _, err := replyConn.WriteTo(result.data, s.clientAddr); err != nil {
				errors.LogErrorInner(context.Background(), err, "UDP return: transparent write back failed")
				return
			}
		}
	}
}

func (s *udpSession) routingContext(ctx context.Context) context.Context {
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Source: bcnet.UDPDestination(bcnet.IPAddress(s.clientAddr.IP), bcnet.Port(s.clientAddr.Port)),
		Local:  bcnet.DestinationFromAddr(s.listener.conn.LocalAddr()),
		Tag:    s.listener.cfg.Tag,
	})
	return session.ContextWithContent(ctx, new(session.Content))
}

func (s *udpSession) setResources(conn net.Conn, reply net.PacketConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:
		conn.Close()
		reply.Close()
		return false
	default:
		s.outbound = conn
		s.replyConn = reply
		return true
	}
}

func (s *udpSession) readUDPResponses(conn net.Conn, out chan<- udpReadResult) {
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		result := udpReadResult{err: err}
		if n > 0 {
			result.data = append([]byte(nil), buf[:n]...)
		}
		select {
		case out <- result:
		case <-s.ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

// listenTransparentReply follows Xray's FakeUDP approach: create a transparent
// socket bound to the intercepted destination, then send replies to the client.
// The client therefore sees packets from the real original destination.
func listenTransparentReply(dest bcnet.Destination) (net.PacketConn, error) {
	network := "udp4"
	if dest.Address.IP().To4() == nil {
		network = "udp6"
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
				sockErr = err
				return
			}
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			if strings.HasSuffix(network, "4") {
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			} else {
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
			}
		})
		if err != nil {
			return err
		}
		return sockErr
	}}
	return lc.ListenPacket(context.Background(), network, dest.NetAddr())
}

// close shuts down the session.
func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.cancel()
		if s.listener.sessions.CompareAndDelete(s.key, s) {
			s.listener.count.Add(-1)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.outbound != nil {
			s.outbound.Close()
		}
		if s.replyConn != nil {
			s.replyConn.Close()
		}
	})
}

// Close stops the UDP listener.
func (l *udpTproxyListener) Close() error {
	if l.cancel != nil {
		l.cancel()
	}
	if l.conn != nil {
		l.conn.Close()
	}
	// Close all sessions.
	l.sessions.Range(func(_, v any) bool {
		v.(*udpSession).close()
		return true
	})
	l.wg.Wait()
	return nil
}
