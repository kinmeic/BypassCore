//go:build linux

// Package inbound implements transparent proxy listeners.
// This file implements UDP TPROXY using IP_TRANSPARENT + IP_RECVORIGDSTADDR.
//
// UDP TPROXY flow:
// 1. iptables TPROXY redirects UDP packets to this listener's port
// 2. We create a socket with IP_TRANSPARENT + IP_RECVORIGDSTADDR
// 3. ReadMsgUDP returns payload + OOB control message containing the
//    original destination (IP_RECVORIGDSTADDR)
// 4. We route by original dest, dial the outbound, and relay packets
// 5. Return packets are written back with the original dest as source
//    (IP_TRANSPARENT allows binding to non-local addresses)
package inbound

import (
	"context"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/eugene/bypasscore/app/dispatcher"
	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	"golang.org/x/sys/unix"
)

// udpTproxyListener is a UDP TPROXY listener.
type udpTproxyListener struct {
	cfg        *Config
	dispatcher *dispatcher.Dispatcher

	conn      *net.UDPConn
	sessions  sync.Map // key: "srcAddr" → *udpSession

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// udpSession represents one client's UDP relay: the outbound connection +
// a goroutine copying return packets back to the client.
type udpSession struct {
	clientAddr  *net.UDPAddr  // client source address
	originalDst bcnet.Destination // original target (from TPROXY)
	outbound    net.Conn      // outbound connection (to proxy/freedom)
	dispatcher *dispatcher.Dispatcher
	listener    *udpTproxyListener

	closeOnce sync.Once
	closed    chan struct{}
}

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

	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
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
		conn:        udpConn,
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

		packet := make([]byte, n)
		copy(packet, buf[:n])

		// Get or create a session for this client.
		key := srcAddr.String()
		sess, _ := l.sessions.LoadOrStore(key, &udpSession{
			clientAddr:  srcAddr,
			originalDst: origDst,
			dispatcher:  l.dispatcher,
			listener:    l,
			closed:      make(chan struct{}),
		})
		s := sess.(*udpSession)

		// Forward the packet to the outbound (lazily dialed on first packet).
		go s.relay(packet, origDst)
	}
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

// relay sends a packet to the outbound and reads back the response.
func (s *udpSession) relay(packet []byte, dest bcnet.Destination) {
	// Dial the outbound (lazily, on first packet for this session).
	if s.outbound == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Route via the dispatcher's router to get the outbound tag.
		// For UDP, we use the dispatcher directly — it will route + dial.
		// But dispatcher.Dispatch expects a net.Conn (stream), not packets.
		// For UDP we bypass the dispatcher and dial directly via the outbound.
		// The dispatcher's OutboundManager gives us the dialer.
		// Actually, we need a simpler path: dial the outbound dialer directly.
		// Let's use the dispatcher's bridge approach but for UDP.
		conn, err := s.dialOutbound(ctx, dest)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "UDP relay: outbound dial failed for ", dest.String())
			s.close()
			return
		}
		s.outbound = conn

		// Start a goroutine to read responses from the outbound and send
		// them back to the client via the tproxy socket.
		go s.returnLoop()
	}

	// Write the packet to the outbound.
	if _, err := s.outbound.Write(packet); err != nil {
		errors.LogErrorInner(context.Background(), err, "UDP relay: write to outbound failed")
		s.close()
	}
}

// dialOutbound routes the destination and dials the outbound connection.
func (s *udpSession) dialOutbound(ctx context.Context, dest bcnet.Destination) (net.Conn, error) {
	// For now, use a direct dial — the dispatcher's routing will be applied
	// via the router. We need access to the router + outbound manager.
	// Since the dispatcher has them, we'll add a helper method.
	return s.dispatcher.DialOutbound(ctx, dest)
}

// returnLoop reads packets from the outbound connection and writes them
// back to the client via the tproxy socket (with source address spoofing).
func (s *udpSession) returnLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-s.closed:
			return
		default:
		}

		n, err := s.outbound.Read(buf)
		if err != nil {
			s.close()
			return
		}

		// Write back to the client via the tproxy UDP socket.
		// We need to spoof the source address as the original destination
		// so the client thinks the response came from the real server.
		// This requires sendmsg with a custom source address (IP_TRANSPARENT allows it).
		if err := s.listener.writeBack(buf[:n], s.clientAddr, s.originalDst); err != nil {
			errors.LogErrorInner(context.Background(), err, "UDP return: write back failed")
			s.close()
			return
		}
	}
}

// writeBack sends a packet to the client. True source-address spoofing
// (so the client sees the response coming from the original destination)
// requires raw sendmsg with IP_TRANSPARENT. For now, WriteToUDP sends from
// the listener's bound address — this works in REDIRECT mode but not in
// true TPROXY mode. Full spoofing is a TODO.
func (l *udpTproxyListener) writeBack(data []byte, client *net.UDPAddr, origDst bcnet.Destination) error {
	_, err := l.conn.WriteToUDP(data, client)
	return err
}

// close shuts down the session.
func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.outbound != nil {
			s.outbound.Close()
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
