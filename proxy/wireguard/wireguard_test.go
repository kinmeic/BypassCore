package wireguard

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	appoutbound "github.com/eugene/bypasscore/app/outbound"
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/common/wgkey"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestCloseBeforeDialDoesNotInitialize(t *testing.T) {
	handler := New("unused", &appoutbound.WireGuardConfig{
		SecretKey: "deliberately invalid",
	})
	if err := handler.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if handler.device != nil || handler.tun != nil || handler.net != nil {
		t.Fatal("closing an unused outbound initialized WireGuard resources")
	}
	_, err := handler.Dial(context.Background(), bcnet.TCPDestination(bcnet.LocalHostIP, 80))
	if err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Dial after Close error = %v, want closed", err)
	}
}

func TestNumericDestinationRejectsUnavailableFamily(t *testing.T) {
	destination := bcnet.TCPDestination(bcnet.LocalHostIPv6, 443)
	if _, err := numericDestination(context.Background(), destination, true, false); err == nil {
		t.Fatal("IPv6 destination accepted by an IPv4-only WireGuard device")
	}
}

func TestPreferredAddress(t *testing.T) {
	addresses := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.0.2.1"),
	}
	if got, ok := preferredAddress(addresses, true, true); !ok || got.String() != "192.0.2.1" {
		t.Fatalf("dual-stack preference = %v, %v; want IPv4", got, ok)
	}
	if got, ok := preferredAddress(addresses, false, true); !ok || got.String() != "2001:db8::1" {
		t.Fatalf("IPv6-only preference = %v, %v; want IPv6", got, ok)
	}
}

func TestHandlerCarriesTCPAndUDP(t *testing.T) {
	localPrivate, localPublic := testKeypair(t)
	peerPrivate, peerPublic := testKeypair(t)

	peerTun, peerNet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, defaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	peerDevice := device.NewDevice(peerTun, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelSilent, "test-peer: "))
	t.Cleanup(peerDevice.Close)
	peerIPC := fmt.Sprintf(
		"private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nallowed_ip=10.77.0.2/32\n",
		wgkey.Hex(peerPrivate), wgkey.Hex(localPublic))
	if err := peerDevice.IpcSet(peerIPC); err != nil {
		t.Fatal(err)
	}
	if err := peerDevice.Up(); err != nil {
		t.Fatal(err)
	}
	listenPort := wireGuardListenPort(t, peerDevice)

	handler := New("test", &appoutbound.WireGuardConfig{
		SecretKey: wgkey.Encode(localPrivate),
		PublicKey: wgkey.Encode(localPublic),
		Address:   []string{"10.77.0.2/32"},
		Peers: []*appoutbound.WireGuardPeerConfig{{
			PublicKey:  wgkey.Encode(peerPublic),
			Endpoint:   net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)),
			AllowedIPs: []string{"10.77.0.0/24"},
		}},
		MTU: defaultMTU,
	})
	t.Cleanup(func() { _ = handler.Close() })

	tcpListener, err := peerNet.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpListener.Close() })
	tcpDone := make(chan error, 1)
	go func() {
		connection, err := tcpListener.Accept()
		if err != nil {
			tcpDone <- err
			return
		}
		defer connection.Close()
		payload := make([]byte, 4)
		if _, err = io.ReadFull(connection, payload); err == nil {
			_, err = connection.Write(payload)
		}
		tcpDone <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tcpConnection, err := handler.Dial(ctx,
		bcnet.TCPDestination(bcnet.ParseAddress("10.77.0.1"), 18080))
	if err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(tcpConnection, []byte("ping")); err != nil {
		t.Fatalf("TCP round trip: %v", err)
	}
	_ = tcpConnection.Close()
	if err := <-tcpDone; err != nil {
		t.Fatalf("TCP peer: %v", err)
	}

	udpListener, err := peerNet.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:18081"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpListener.Close() })
	udpDone := make(chan error, 1)
	go func() {
		payload := make([]byte, 64)
		n, address, err := udpListener.ReadFrom(payload)
		if err == nil {
			_, err = udpListener.WriteTo(payload[:n], address)
		}
		udpDone <- err
	}()
	udpConnection, err := handler.Dial(ctx,
		bcnet.UDPDestination(bcnet.ParseAddress("10.77.0.1"), 18081))
	if err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(udpConnection, []byte("pong")); err != nil {
		t.Fatalf("UDP round trip: %v", err)
	}
	_ = udpConnection.Close()
	if err := <-udpDone; err != nil {
		t.Fatalf("UDP peer: %v", err)
	}
}

func testKeypair(t *testing.T) ([wgkey.Size]byte, [wgkey.Size]byte) {
	t.Helper()
	private, err := wgkey.GeneratePrivate()
	if err != nil {
		t.Fatal(err)
	}
	public, err := wgkey.Public(private)
	if err != nil {
		t.Fatal(err)
	}
	return private, public
}

func wireGuardListenPort(t *testing.T, wgDevice *device.Device) int {
	t.Helper()
	state, err := wgDevice.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(state, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port, err := strconv.Atoi(strings.TrimPrefix(line, "listen_port="))
			if err == nil && port > 0 {
				return port
			}
		}
	}
	t.Fatalf("WireGuard state has no listen port: %q", state)
	return 0
}

func roundTrip(connection net.Conn, payload []byte) error {
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := connection.Write(payload); err != nil {
		return err
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		return err
	}
	if string(response) != string(payload) {
		return fmt.Errorf("response %q, want %q", response, payload)
	}
	return nil
}
