package tls

import (
	"encoding/binary"
	"testing"
)

// buildClientHello constructs a minimal TLS 1.2 ClientHello with the given SNI.
// This produces valid TLS record bytes that SniffSNI can parse.
func buildClientHello(sni string) []byte {
	// Server name extension (type 0x0000).
	hostBytes := []byte(sni)
	sniExt := []byte{0x00, 0x00} // ext type
	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(2+1+2+len(hostBytes))) // list_len + name_type + name_len + name
	sniExt = append(sniExt, extLen...)
	listLen := make([]byte, 2)
	binary.BigEndian.PutUint16(listLen, uint16(1+2+len(hostBytes)))
	sniExt = append(sniExt, listLen...)
	sniExt = append(sniExt, 0x00) // name_type = host_name
	nameLen := make([]byte, 2)
	binary.BigEndian.PutUint16(nameLen, uint16(len(hostBytes)))
	sniExt = append(sniExt, nameLen...)
	sniExt = append(sniExt, hostBytes...)

	// Extensions total length
	extTotalLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extTotalLen, uint16(len(sniExt)))

	// Compression methods: 1 method (null)
	cm := []byte{0x01, 0x00}

	// Cipher suites: 1 suite (TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F)
	cs := []byte{0x00, 0x02, 0x00, 0x2F}

	// Session ID: empty
	sid := []byte{0x00}

	// Random: 32 bytes of zeros
	random := make([]byte, 32)

	// Version: TLS 1.2 = 0x0303
	version := []byte{0x03, 0x03}

	// Assemble ClientHello body (after handshake header)
	helloBody := append(version, random...)
	helloBody = append(helloBody, sid...)
	helloBody = append(helloBody, cs...)
	helloBody = append(helloBody, cm...)
	helloBody = append(helloBody, extTotalLen...)
	helloBody = append(helloBody, sniExt...)

	// Handshake header: type=ClientHello(0x01), length=3 bytes
	hsLen := len(helloBody)
	handshake := []byte{0x01, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}
	handshake = append(handshake, helloBody...)

	// TLS record header: type=Handshake(0x16), version=0x0301, length
	recLen := len(handshake)
	record := []byte{0x16, 0x03, 0x01, byte(recLen >> 8), byte(recLen)}
	record = append(record, handshake...)

	return record
}

// TestSniffSNI_ValidClientHello verifies SNI extraction from a synthetic
// ClientHello.
func TestSniffSNI_ValidClientHello(t *testing.T) {
	data := buildClientHello("www.example.com")
	got := SniffSNI(data)
	if got != "www.example.com" {
		t.Errorf("SniffSNI = %q, want www.example.com", got)
	}
}

// TestSniffSNI_NoSNI returns "" for a ClientHello without SNI extension.
func TestSniffSNI_NoSNI(t *testing.T) {
	// Build a ClientHello with a different extension (e.g. supported_versions 0x002B)
	// instead of server_name. Simplest: just modify buildClientHello to use ext type 0x002B.
	data := buildClientHelloWithExt(0x002B, []byte{0x03, 0x04})
	got := SniffSNI(data)
	if got != "" {
		t.Errorf("SniffSNI(no SNI) = %q, want empty", got)
	}
}

// TestSniffSNI_NotTLS returns "" for non-TLS data.
func TestSniffSNI_NotTLS(t *testing.T) {
	if got := SniffSNI([]byte("GET / HTTP/1.1\r\n")); got != "" {
		t.Errorf("SniffSNI(HTTP) = %q, want empty", got)
	}
}

// TestSniffSNI_TooShort returns "" for truncated data.
func TestSniffSNI_TooShort(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x16},
		{0x16, 0x03},
		{0x16, 0x03, 0x01, 0x00, 0x05}, // record says 5 bytes but no handshake
	}
	for _, data := range cases {
		if got := SniffSNI(data); got != "" {
			t.Errorf("SniffSNI(%v) = %q, want empty", data, got)
		}
	}
}

// TestSniffSNI_NotHandshake returns "" when record type != 0x16.
func TestSniffSNI_NotHandshake(t *testing.T) {
	data := []byte{0x14, 0x03, 0x01, 0x00, 0x01, 0x00} // ChangeCipherSpec
	if got := SniffSNI(data); got != "" {
		t.Errorf("SniffSNI(ChangeCipherSpec) = %q, want empty", got)
	}
}

// TestSniffSNI_NotClientHello returns "" when handshake type != 0x01.
func TestSniffSNI_NotClientHello(t *testing.T) {
	// Build a record with handshake type = ServerHello (0x02).
	data := buildRecord(0x02, []byte{0x03, 0x03})
	if got := SniffSNI(data); got != "" {
		t.Errorf("SniffSNI(ServerHello) = %q, want empty", got)
	}
}

// TestSniffSNI_EmptySNI returns "" for a valid ClientHello with an empty SNI.
func TestSniffSNI_EmptySNI(t *testing.T) {
	data := buildClientHello("")
	got := SniffSNI(data)
	if got != "" {
		t.Errorf("SniffSNI(empty SNI) = %q, want empty", got)
	}
}

// TestSniffSNI_FragmentedClamped verifies that a ClientHello whose declared
// length exceeds the available data is still parsed (clamped).
func TestSniffSNI_FragmentedClamped(t *testing.T) {
	full := buildClientHello("frag.example.com")
	// Truncate to half the data — SniffSNI should clamp and still try.
	half := full[:len(full)/2]
	// It may or may not find the SNI (depends on where the truncation falls),
	// but it must NOT panic.
	_ = SniffSNI(half)
}

func TestSniffSNI_ClientHelloAcrossRecords(t *testing.T) {
	original := buildClientHello("fragmented.example")
	payload := original[5:]
	cut := len(payload) / 2
	fragmented := append([]byte{0x16, 0x03, 0x01, byte(cut >> 8), byte(cut)}, payload[:cut]...)
	rest := len(payload) - cut
	fragmented = append(fragmented, 0x16, 0x03, 0x01, byte(rest>>8), byte(rest))
	fragmented = append(fragmented, payload[cut:]...)

	if got := SniffSNI(fragmented); got != "fragmented.example" {
		t.Fatalf("SniffSNI(fragmented) = %q", got)
	}
	if _, needMore := SniffSNIWithStatus(fragmented[:len(fragmented)-1]); !needMore {
		t.Fatal("truncated second TLS record should request more data")
	}
}

// --- helpers ---

func buildClientHelloWithExt(extType uint16, extData []byte) []byte {
	ext := make([]byte, 4)
	binary.BigEndian.PutUint16(ext[0:2], extType)
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(extData)))
	ext = append(ext, extData...)

	extTotalLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extTotalLen, uint16(len(ext)))

	cm := []byte{0x01, 0x00}
	cs := []byte{0x00, 0x02, 0x00, 0x2F}
	sid := []byte{0x00}
	random := make([]byte, 32)
	version := []byte{0x03, 0x03}

	helloBody := append(version, random...)
	helloBody = append(helloBody, sid...)
	helloBody = append(helloBody, cs...)
	helloBody = append(helloBody, cm...)
	helloBody = append(helloBody, extTotalLen...)
	helloBody = append(helloBody, ext...)

	hsLen := len(helloBody)
	handshake := []byte{0x01, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}
	handshake = append(handshake, helloBody...)

	recLen := len(handshake)
	record := []byte{0x16, 0x03, 0x01, byte(recLen >> 8), byte(recLen)}
	record = append(record, handshake...)
	return record
}

func buildRecord(hsType byte, body []byte) []byte {
	handshake := []byte{hsType, 0x00, byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	recLen := len(handshake)
	record := []byte{0x16, 0x03, 0x01, byte(recLen >> 8), byte(recLen)}
	record = append(record, handshake...)
	return record
}
