// Package quic decrypts QUIC v1/draft-29 Initial packets and extracts TLS SNI.
package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	tlsproto "github.com/eugene/bypasscore/common/protocol/tls"
)

var (
	saltDraft29 = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	saltV1      = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	errNotQUIC  = errors.New("not a supported QUIC Initial packet")
)

// SniffSNI returns SNI and whether additional Initial packets may complete the
// ClientHello. data may contain coalesced or concatenated long-header packets.
func SniffSNI(data []byte) (string, bool) {
	if len(data) == 0 {
		return "", true
	}
	cryptoData := make([]byte, 0, 32768)
	for len(data) > 0 {
		consumed, fragments, initial, err := decryptInitial(data)
		if err != nil || consumed <= 0 {
			return "", false
		}
		data = data[consumed:]
		if !initial {
			continue
		}
		for _, fragment := range fragments {
			end := fragment.offset + len(fragment.data)
			if end > 32768 {
				return "", false
			}
			if end > len(cryptoData) {
				cryptoData = append(cryptoData, make([]byte, end-len(cryptoData))...)
			}
			copy(cryptoData[fragment.offset:end], fragment.data)
		}
		if host, more := tlsproto.SniffClientHelloHandshake(cryptoData); host != "" || !more {
			return host, false
		}
	}
	return "", true
}

type cryptoFragment struct {
	offset int
	data   []byte
}

func decryptInitial(packet []byte) (int, []cryptoFragment, bool, error) {
	if len(packet) < 7 || packet[0]&0xc0 != 0xc0 {
		return 0, nil, false, errNotQUIC
	}
	work := append([]byte(nil), packet...)
	version := binary.BigEndian.Uint32(work[1:5])
	if version != 1 && version != 0xff00001d {
		return 0, nil, false, errNotQUIC
	}
	initial := (work[0]&0x30)>>4 == 0
	pos := 5
	dcid, next, ok := readLengthPrefixed(work, pos)
	if !ok {
		return 0, nil, false, errNotQUIC
	}
	pos = next
	_, pos, ok = readLengthPrefixed(work, pos)
	if !ok {
		return 0, nil, false, errNotQUIC
	}
	if initial {
		tokenLen, n, ok := readVarint(work[pos:])
		if !ok || tokenLen > uint64(len(work)) {
			return 0, nil, false, errNotQUIC
		}
		pos += n
		if uint64(len(work)-pos) < tokenLen {
			return 0, nil, false, io.ErrUnexpectedEOF
		}
		pos += int(tokenLen)
	}
	packetLen, n, ok := readVarint(work[pos:])
	if !ok || packetLen < 4 {
		return 0, nil, false, errNotQUIC
	}
	pos += n
	pnOffset := pos
	end := pnOffset + int(packetLen)
	if end > len(work) {
		return 0, nil, false, io.ErrUnexpectedEOF
	}
	if !initial {
		return end, nil, false, nil
	}
	if pnOffset+4+aes.BlockSize > end {
		return 0, nil, false, errNotQUIC
	}

	salt := saltV1
	if version == 0xff00001d {
		salt = saltDraft29
	}
	secret, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return 0, nil, false, err
	}
	clientSecret, err := expandLabel(secret, "client in", 32)
	if err != nil {
		return 0, nil, false, err
	}
	hpKey, _ := expandLabel(clientSecret, "quic hp", 16)
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return 0, nil, false, err
	}
	mask := make([]byte, aes.BlockSize)
	block.Encrypt(mask, work[pnOffset+4:pnOffset+4+aes.BlockSize])
	work[0] ^= mask[0] & 0x0f
	pnLen := int(work[0]&3) + 1
	if pnOffset+pnLen > end {
		return 0, nil, false, errNotQUIC
	}
	var packetNumber uint64
	for i := 0; i < pnLen; i++ {
		work[pnOffset+i] ^= mask[i+1]
		packetNumber = packetNumber<<8 | uint64(work[pnOffset+i])
	}

	key, _ := expandLabel(clientSecret, "quic key", 16)
	iv, _ := expandLabel(clientSecret, "quic iv", 12)
	keyBlock, err := aes.NewCipher(key)
	if err != nil {
		return 0, nil, false, err
	}
	aead, err := cipher.NewGCM(keyBlock)
	if err != nil {
		return 0, nil, false, err
	}
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(packetNumber >> (8 * i))
	}
	headerEnd := pnOffset + pnLen
	plaintext, err := aead.Open(nil, nonce, work[headerEnd:end], work[:headerEnd])
	if err != nil {
		return 0, nil, false, err
	}
	fragments, err := parseInitialFrames(plaintext)
	return end, fragments, true, err
}

func parseInitialFrames(data []byte) ([]cryptoFragment, error) {
	var fragments []cryptoFragment
	for len(data) > 0 {
		typ, n, ok := readVarint(data)
		if !ok {
			return nil, io.ErrUnexpectedEOF
		}
		data = data[n:]
		switch typ {
		case 0, 1: // padding, ping
		case 2, 3: // ACK / ACK_ECN
			var count uint64
			for field := 0; field < 4; field++ {
				value, used, ok := readVarint(data)
				if !ok {
					return nil, io.ErrUnexpectedEOF
				}
				data = data[used:]
				if field == 2 {
					count = value
				}
			}
			for i := uint64(0); i < count*2; i++ {
				_, used, ok := readVarint(data)
				if !ok {
					return nil, io.ErrUnexpectedEOF
				}
				data = data[used:]
			}
			if typ == 3 {
				for range 3 {
					_, used, ok := readVarint(data)
					if !ok {
						return nil, io.ErrUnexpectedEOF
					}
					data = data[used:]
				}
			}
		case 6: // CRYPTO
			offset, used, ok := readVarint(data)
			if !ok {
				return nil, io.ErrUnexpectedEOF
			}
			data = data[used:]
			length, used, ok := readVarint(data)
			if !ok || length > uint64(len(data)) {
				return nil, io.ErrUnexpectedEOF
			}
			data = data[used:]
			fragments = append(fragments, cryptoFragment{offset: int(offset), data: append([]byte(nil), data[:length]...)})
			data = data[length:]
		case 0x1c: // CONNECTION_CLOSE
			for range 2 {
				_, used, ok := readVarint(data)
				if !ok {
					return nil, io.ErrUnexpectedEOF
				}
				data = data[used:]
			}
			length, used, ok := readVarint(data)
			if !ok || length > uint64(len(data)-used) {
				return nil, io.ErrUnexpectedEOF
			}
			data = data[used+int(length):]
		default:
			return nil, errNotQUIC
		}
	}
	return fragments, nil
}

func expandLabel(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

func readLengthPrefixed(data []byte, pos int) ([]byte, int, bool) {
	if pos >= len(data) {
		return nil, pos, false
	}
	length := int(data[pos])
	pos++
	if length > 20 || pos+length > len(data) {
		return nil, pos, false
	}
	return data[pos : pos+length], pos + length, true
}

func readVarint(data []byte) (uint64, int, bool) {
	if len(data) == 0 {
		return 0, 0, false
	}
	length := 1 << (data[0] >> 6)
	if length > 8 || len(data) < length {
		return 0, 0, false
	}
	value := uint64(data[0] & 0x3f)
	for i := 1; i < length; i++ {
		value = value<<8 | uint64(data[i])
	}
	return value, length, true
}
