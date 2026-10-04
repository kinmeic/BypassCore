package netstack

import (
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestCloseUnblocksPacketNotification(t *testing.T) {
	device, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	tun := device.(*netTun)
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer packet.DecRef()
	notified := make(chan struct{})
	go func() {
		var packets stack.PacketBufferList
		packets.PushBack(packet)
		_, _ = tun.ep.WritePackets(packets)
		close(notified)
	}()
	closed := make(chan struct{})
	go func() { _ = device.Close(); close(closed) }()
	for _, done := range []chan struct{}{notified, closed} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("shutdown retained a packet notification")
		}
	}
	if _, err := device.Read([][]byte{make([]byte, 1500)}, []int{0}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read after Close = %v", err)
	}
	if _, err := device.Write([][]byte{{0x40}}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write after Close = %v", err)
	}
}

func TestCreateNetTUNRejectsDuplicateAddress(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	device, _, err := CreateNetTUN([]netip.Addr{ip, ip}, nil, 1420)
	if device != nil {
		_ = device.Close()
	}
	if err == nil {
		t.Fatal("duplicate local address accepted")
	}
}
