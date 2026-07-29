package inbound

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/eugene/bypasscore/app/dialer"
	"github.com/eugene/bypasscore/app/dispatcher"
	"github.com/eugene/bypasscore/common"
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/features/routing"
	xproxy "golang.org/x/net/proxy"
)

type socksTestManager struct {
	dialer dialer.Dialer
}

func (m *socksTestManager) GetDialer(string) dialer.Dialer  { return m.dialer }
func (m *socksTestManager) GetDefaultDialer() dialer.Dialer { return m.dialer }

type socksEchoDialer struct {
	destinations chan bcnet.Destination
	echoAddress  string
}

type socksBlockingDialer struct {
	started chan struct{}
}

type socksRecordingRouter struct {
	routing.DefaultRouter
	domains chan string
}

func (r *socksRecordingRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	r.domains <- ctx.GetTargetDomain()
	return nil, common.ErrNoClue
}

func (d *socksEchoDialer) Tag() string { return "test" }

func (d *socksEchoDialer) Dial(_ context.Context, dest bcnet.Destination) (net.Conn, error) {
	d.destinations <- dest
	return net.Dial("tcp", d.echoAddress)
}

func (d *socksBlockingDialer) Tag() string { return "blocking" }

func (d *socksBlockingDialer) Dial(ctx context.Context, _ bcnet.Destination) (net.Conn, error) {
	select {
	case d.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func startSOCKSTestEchoServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	return listener
}

func TestSOCKS5InboundConnectPreservesDomain(t *testing.T) {
	echoListener := startSOCKSTestEchoServer(t)
	defer echoListener.Close()

	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	echo := &socksEchoDialer{
		destinations: make(chan bcnet.Destination, 1),
		echoAddress:  echoListener.Addr().String(),
	}
	router := &socksRecordingRouter{domains: make(chan string, 1)}
	d := dispatcher.New(router, &socksTestManager{dialer: echo}, nil)
	listener := New(&Config{Tag: "caddy", Type: "socks", Port: port, Network: "tcp"}, d)
	if err := listener.Start(); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	socksDialer, err := xproxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", bcnet.Port(port).String()), nil, xproxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := socksDialer.Dial("tcp", "route.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	select {
	case dest := <-echo.destinations:
		if dest.Network != bcnet.Network_TCP || dest.Address.String() != "route.example" || dest.Port != 443 {
			t.Fatalf("routed destination = %s, want tcp:route.example:443", dest.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS5 destination was not dispatched")
	}
	select {
	case domain := <-router.domains:
		if domain != "route.example" {
			t.Fatalf("routing context domain = %q, want route.example", domain)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS5 domain did not reach the router")
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "ping" {
		t.Fatalf("echo response = %q, want ping", response)
	}
}

func TestReadSOCKS5ConnectRequest(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		_, _ = client.Write([]byte{
			5, 1, 0, 3, 11,
			'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
			0x01, 0xbb,
		})
	}()
	dest, reply, err := readSOCKS5ConnectRequest(server)
	if err != nil {
		t.Fatal(err)
	}
	if reply != socks5ReplySucceeded || dest.String() != "tcp:example.com:443" {
		t.Fatalf("request = %s reply=%d", dest.String(), reply)
	}
}

func TestReadSOCKS5ConnectRequestRejectsUnsupportedCommand(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		_, _ = client.Write([]byte{5, 3, 0, 1, 127, 0, 0, 1, 0, 53})
	}()
	_, reply, err := readSOCKS5ConnectRequest(server)
	if err == nil || reply != socks5ReplyCommandNotSupported {
		t.Fatalf("err=%v reply=%d, want command-not-supported", err, reply)
	}
}

func TestReadSOCKS5ConnectRequestIPv6(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		_, _ = client.Write([]byte{
			5, 1, 0, 4,
			0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 1,
			0x01, 0xbb,
		})
	}()
	dest, reply, err := readSOCKS5ConnectRequest(server)
	if err != nil {
		t.Fatal(err)
	}
	if reply != socks5ReplySucceeded || dest.NetAddr() != "[2001:db8::1]:443" {
		t.Fatalf("request = %s reply=%d", dest.String(), reply)
	}
}

func TestNegotiateSOCKS5NoAuthRejectsUnavailableMethod(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- negotiateSOCKS5NoAuth(server) }()
	if _, err := client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if response[0] != 5 || response[1] != socks5MethodNotAvailable {
		t.Fatalf("method response = %v", response)
	}
	if err := <-done; err == nil {
		t.Fatal("missing no-authentication method was accepted")
	}
}

func TestSOCKS5InboundCloseCancelsPendingOutboundDial(t *testing.T) {
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	blocking := &socksBlockingDialer{started: make(chan struct{}, 1)}
	d := dispatcher.New(&socksRecordingRouter{domains: make(chan string, 1)}, &socksTestManager{dialer: blocking}, nil)
	listener := New(&Config{Tag: "caddy", Type: "socks", Port: port, Network: "tcp"}, d)
	if err := listener.Start(); err != nil {
		t.Fatal(err)
	}

	client, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", bcnet.Port(port).String()))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(client, method); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0, 80}); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		_ = listener.Close()
		t.Fatal("outbound dial did not start")
	}

	closed := make(chan error, 1)
	go func() { closed <- listener.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener close did not cancel pending SOCKS5 outbound dial")
	}
}

func TestSOCKS5ReplyForError(t *testing.T) {
	if got := socks5ReplyForError(&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}); got != socks5ReplyConnectionRefused {
		t.Fatalf("connection-refused reply = %d", got)
	}
	if got := socks5ReplyForError(stderrors.New("unknown")); got != socks5ReplyGeneralFailure {
		t.Fatalf("general failure reply = %d", got)
	}
}
