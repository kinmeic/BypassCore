package geodata

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDecodeVarintRejectsOverflow(t *testing.T) {
	data := bytes.Repeat([]byte{0xff}, 9)
	data = append(data, 2)
	if _, err := decodeVarint(bufio.NewReader(bytes.NewReader(data))); err == nil {
		t.Fatal("overflowing tenth varint byte accepted")
	}
}

func TestFindRejectsForgedLengthWithoutAllocatingBody(t *testing.T) {
	data := binary.AppendUvarint([]byte{0x0a}, 1<<40)
	data = append(data, 0x0a, 2, 'C', 'N')
	if _, err := find(bytes.NewReader(data), []byte("CN"), true); err == nil {
		t.Fatal("truncated entry with a forged length accepted")
	}
}

func TestFindReadsMatchingEntry(t *testing.T) {
	body := []byte{0x0a, 2, 'C', 'N', 0x12, 0}
	data := binary.AppendUvarint([]byte{0x0a}, uint64(len(body)))
	data = append(data, body...)
	got, err := find(bytes.NewReader(data), []byte("CN"), true)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("find = %x, err=%v", got, err)
	}
}
