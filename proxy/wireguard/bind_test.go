package wireguard

import (
	"bytes"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

type recordingBind struct {
	conn.Bind
	sent [][]byte
}

func (b *recordingBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	b.sent = append(b.sent, bufs...)
	return nil
}

func TestReservedBindInjectsReservedBytes(t *testing.T) {
	base := &recordingBind{}
	bind := &reservedBind{Bind: base, reserved: [3]byte{138, 76, 29}}
	packet := []byte{0x01, 0x00, 0x00, 0x00, 0xaa}
	short := []byte{0x01, 0x00}
	if err := bind.Send([][]byte{packet, short}, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if want := []byte{0x01, 138, 76, 29, 0xaa}; !bytes.Equal(base.sent[0], want) {
		t.Fatalf("injected packet = %v, want %v", base.sent[0], want)
	}
	if !bytes.Equal(base.sent[1], []byte{0x01, 0x00}) {
		t.Fatalf("short packet modified: %v", base.sent[1])
	}
}
