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
	commonmetrics "github.com/eugene/bypasscore/common/metrics"
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
	// sourceCounts is guarded by createMu and contains entries only for source
	// IPs with at least one active session.
	sourceCounts map[string]int
	limits       atomic.Pointer[udpResourceLimits]
	runtimeTag   atomic.Pointer[string]

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	onState func(string, error)
}

// udpSession represents one client's UDP relay: the outbound connection +
// a goroutine copying return packets back to the client.
type udpSession struct {
	key         string
	sourceKey   string
	clientAddr  *net.UDPAddr      // client source address
	originalDst bcnet.Destination // original target (from TPROXY)
	outbound    net.Conn          // outbound connection (to proxy/freedom)
	replyConn   net.PacketConn    // transparent socket bound to originalDst
	listener    *udpTproxyListener
	inboundTag  string
	ctx         context.Context
	cancel      context.CancelFunc
	packets     chan []byte
	queuedBytes atomic.Int64

	mu        sync.Mutex
	closeOnce sync.Once
	closed    chan struct{}
}

func (l *udpTproxyListener) setLimits(limits udpResourceLimits) {
	copy := limits
	l.limits.Store(&copy)
}

func (l *udpTproxyListener) setTag(tag string) { value := tag; l.runtimeTag.Store(&value) }
func (l *udpTproxyListener) inboundTag() string {
	if value := l.runtimeTag.Load(); value != nil {
		return *value
	}
	return ""
}

func (l *udpTproxyListener) currentLimits() udpResourceLimits {
	if limits := l.limits.Load(); limits != nil {
		return *limits
	}
	return udpResourceLimits{}
}

// startUDP creates a UDP TPROXY listener.
func startUDP(cfg *Config, d *dispatcher.Dispatcher, onState func(string, error)) (*udpTproxyListener, error) {
	limits, err := udpResourceLimitsFromConfig(cfg)
	if err != nil {
		return nil, err
	}
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
		cfg:          cfg,
		dispatcher:   d,
		conn:         udpConn,
		sourceCounts: make(map[string]int),
		onState:      onState,
	}
	l.setLimits(limits)
	l.setTag(cfg.Tag)
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
	degraded := false

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
			if !isRetryableNetworkError(err) {
				if l.onState != nil {
					l.onState("failed", err)
				}
				return
			}
			if !degraded && l.onState != nil {
				l.onState("degraded", err)
			}
			degraded = true
			continue
		}
		if degraded {
			if l.onState != nil {
				l.onState("running", nil)
			}
			degraded = false
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
			commonmetrics.Inc("bypasscore_udp_dropped_total", "inbound", l.inboundTag(), "reason", "session_limit")
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
	sourceKey := src.IP.String()
	limits := l.currentLimits()
	if l.ctx.Err() != nil || l.count.Load() >= limits.maxSessions ||
		l.sourceCounts[sourceKey] >= limits.maxSessionsPerSource {
		return nil
	}
	ctx, cancel := context.WithCancel(l.ctx)
	s := &udpSession{
		key:         key,
		sourceKey:   sourceKey,
		clientAddr:  src,
		originalDst: dst,
		listener:    l,
		inboundTag:  l.inboundTag(),
		ctx:         ctx,
		cancel:      cancel,
		packets:     make(chan []byte, limits.queuePackets),
		closed:      make(chan struct{}),
	}
	l.sessions.Store(key, s)
	l.count.Add(1)
	l.sourceCounts[sourceKey]++
	commonmetrics.Add("bypasscore_udp_sessions_active", 1, "inbound", s.inboundTag)
	commonmetrics.Inc("bypasscore_udp_sessions_created_total", "inbound", l.inboundTag())
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
		if queued+size > s.listener.currentLimits().queueBytes {
			commonmetrics.Inc("bypasscore_udp_dropped_total", "inbound", s.inboundTag, "reason", "queue_bytes")
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
		commonmetrics.Inc("bypasscore_udp_dropped_total", "inbound", s.inboundTag, "reason", "queue_packets")
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
	limits := s.listener.currentLimits()
collectLoop:
	for len(pending) < limits.sniffMaxPackets {
		_, _, needMore := s.listener.dispatcher.SniffPacketMetadata(pending)
		if !needMore {
			break
		}
		timer := time.NewTimer(limits.sniffWait)
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
		if len(pending) == 0 || len(pending) >= limits.sniffMaxPackets {
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
	limits = s.listener.currentLimits()
	timer := time.NewTimer(limits.idleTimeout)
	defer timer.Stop()
	resetTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		limits = s.listener.currentLimits()
		timer.Reset(limits.idleTimeout)
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
		Tag:    s.inboundTag,
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
		s.listener.removeSession(s)
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

func (l *udpTproxyListener) removeSession(s *udpSession) {
	l.createMu.Lock()
	defer l.createMu.Unlock()
	if !l.sessions.CompareAndDelete(s.key, s) {
		return
	}
	l.count.Add(-1)
	commonmetrics.Add("bypasscore_udp_sessions_active", -1, "inbound", s.inboundTag)
	if remaining := l.sourceCounts[s.sourceKey] - 1; remaining > 0 {
		l.sourceCounts[s.sourceKey] = remaining
	} else {
		delete(l.sourceCounts, s.sourceKey)
	}
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
