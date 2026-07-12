// Package tls implements TLS ClientHello SNI sniffing. Given the first bytes
// of a TCP connection, it parses the TLS ClientHello to extract the Server
// Name Indication (SNI) extension value, enabling domain-based routing for
// transparent proxy flows that arrive as IP:port.
package tls

import (
	"encoding/binary"
)

// SniffSNI parses a TLS ClientHello from the given bytes and returns the SNI
// hostname, or "" if the bytes are not a valid ClientHello or no SNI is present.
//
// TLS record: ContentType(1) Version(2) Length(2) → Handshake:
// HandshakeType(1) Length(3) Version(2) Random(32) SessionID(1+var)
// CipherSuites(2+var) CompressionMethods(1+var) Extensions(2+var)
func SniffSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// TLS record header
	if data[0] != 0x16 { // ContentType = Handshake
		return ""
	}
	// record length
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recLen < 4 || len(data) < 5+recLen {
		// May be a fragmented ClientHello; try with what we have.
		recLen = len(data) - 5
		if recLen < 4 {
			return ""
		}
	}
	data = data[5 : 5+recLen]

	// Handshake header
	if data[0] != 0x01 { // HandshakeType = ClientHello
		return ""
	}
	// handshake length (3 bytes)
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if hsLen > len(data)-4 {
		hsLen = len(data) - 4
	}
	data = data[4 : 4+hsLen]

	// Version(2) + Random(32)
	if len(data) < 34 {
		return ""
	}
	data = data[34:]

	// Session ID
	if len(data) < 1 {
		return ""
	}
	sidLen := int(data[0])
	data = data[1:]
	if len(data) < sidLen+2 {
		return ""
	}
	data = data[sidLen:]

	// Cipher suites (2-byte length)
	csLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < csLen+1 {
		return ""
	}
	data = data[csLen:]

	// Compression methods (1-byte length)
	cmLen := int(data[0])
	data = data[1:]
	if len(data) < cmLen+2 {
		return ""
	}
	data = data[cmLen:]

	// Extensions (2-byte total length)
	extTotalLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if extTotalLen > len(data) {
		extTotalLen = len(data)
	}
	data = data[:extTotalLen]

	// Iterate extensions
	for len(data) >= 4 {
		extType := binary.BigEndian.Uint16(data[:2])
		extLen := int(binary.BigEndian.Uint16(data[2:4]))
		if len(data) < 4+extLen {
			break
		}
		extData := data[4 : 4+extLen]
		data = data[4+extLen:]

		if extType == 0x0000 { // server_name extension
			return parseSNIExtension(extData)
		}
	}
	return ""
}

// parseSNIExtension extracts the hostname from the server_name extension data.
func parseSNIExtension(data []byte) string {
	// server_name list length (2 bytes)
	if len(data) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if listLen > len(data) {
		listLen = len(data)
	}
	data = data[:listLen]

	// Each entry: name_type(1) + name_length(2) + name
	if len(data) < 3 {
		return ""
	}
	// name_type must be 0 (host_name)
	if data[0] != 0 {
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[1:3]))
	if len(data) < 3+nameLen {
		return ""
	}
	return string(data[3 : 3+nameLen])
}
