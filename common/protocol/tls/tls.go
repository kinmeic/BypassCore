// Package tls implements bounded TLS ClientHello SNI sniffing for transparent
// proxy connections.
package tls

import "encoding/binary"

const maxTLSHandshake = 1 << 20

// SniffSNI returns the SNI hostname from a complete TLS ClientHello.
func SniffSNI(data []byte) string {
	host, _ := SniffSNIWithStatus(data)
	return host
}

// SniffClientHelloHandshake parses TLS handshake bytes without a TLS record
// wrapper. QUIC CRYPTO frames carry ClientHello in this form.
func SniffClientHelloHandshake(data []byte) (host string, needMore bool) {
	if len(data) < 4 {
		return "", true
	}
	if data[0] != 0x01 {
		return "", false
	}
	length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if length < 34 || length > maxTLSHandshake {
		return "", false
	}
	if len(data) < 4+length {
		return "", true
	}
	return parseClientHello(data[4 : 4+length]), false
}

// SniffSNIWithStatus returns the hostname and whether a valid-looking TLS
// ClientHello needs more bytes. Handshake bytes are reassembled across TLS
// records instead of assuming the ClientHello is contained in the first one.
func SniffSNIWithStatus(data []byte) (host string, needMore bool) {
	if len(data) == 0 {
		return "", true
	}
	if data[0] != 0x16 {
		return "", false
	}
	if len(data) >= 5 {
		recordLen := int(binary.BigEndian.Uint16(data[3:5]))
		if recordLen > 0 && recordLen <= 18432 && len(data) >= 5+recordLen {
			payload := data[5 : 5+recordLen]
			if len(payload) >= 4 {
				handshakeLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
				if payload[0] == 0x01 && handshakeLen >= 34 && 4+handshakeLen <= len(payload) {
					// The overwhelmingly common single-record ClientHello can
					// be parsed directly without allocating a reassembly copy.
					return parseClientHello(payload[4 : 4+handshakeLen]), false
				}
			}
		}
	}

	handshake := make([]byte, 0, len(data))
	for offset := 0; ; {
		if len(data)-offset < 5 {
			return "", true
		}
		if data[offset] != 0x16 {
			return "", false
		}
		recordLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		if recordLen == 0 || recordLen > 18432 {
			return "", false
		}
		if len(data)-offset-5 < recordLen {
			return "", true
		}
		handshake = append(handshake, data[offset+5:offset+5+recordLen]...)
		offset += 5 + recordLen

		if len(handshake) >= 1 && handshake[0] != 0x01 {
			return "", false
		}
		if len(handshake) >= 4 {
			handshakeLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if handshakeLen < 34 || handshakeLen > maxTLSHandshake {
				return "", false
			}
			if len(handshake) >= 4+handshakeLen {
				return parseClientHello(handshake[4 : 4+handshakeLen]), false
			}
		}
		if offset == len(data) {
			return "", true
		}
	}
}

func parseClientHello(data []byte) string {
	// Version(2) + Random(32)
	if len(data) < 35 {
		return ""
	}
	data = data[34:]

	sidLen := int(data[0])
	data = data[1:]
	if len(data) < sidLen+2 {
		return ""
	}
	data = data[sidLen:]

	csLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if csLen == 0 || csLen%2 != 0 || len(data) < csLen+1 {
		return ""
	}
	data = data[csLen:]

	compressionLen := int(data[0])
	data = data[1:]
	if compressionLen == 0 || len(data) < compressionLen {
		return ""
	}
	data = data[compressionLen:]
	if len(data) == 0 { // Extensions are optional in old ClientHello messages.
		return ""
	}
	if len(data) < 2 {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if extensionsLen != len(data) {
		return ""
	}

	for len(data) > 0 {
		if len(data) < 4 {
			return ""
		}
		typ := binary.BigEndian.Uint16(data[:2])
		length := int(binary.BigEndian.Uint16(data[2:4]))
		data = data[4:]
		if len(data) < length {
			return ""
		}
		if typ == 0 {
			return parseSNIExtension(data[:length])
		}
		data = data[length:]
	}
	return ""
}

func parseSNIExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if listLen != len(data) {
		return ""
	}
	for len(data) > 0 {
		if len(data) < 3 {
			return ""
		}
		nameType := data[0]
		nameLen := int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if nameLen == 0 || len(data) < nameLen {
			return ""
		}
		if nameType == 0 {
			name := data[:nameLen]
			for _, char := range name {
				if char <= ' ' {
					return ""
				}
			}
			if name[len(name)-1] == '.' {
				return ""
			}
			return string(name)
		}
		data = data[nameLen:]
	}
	return ""
}
