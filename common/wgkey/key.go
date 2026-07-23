// Package wgkey implements WireGuard Curve25519 key parsing and generation.
package wgkey

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const Size = 32

// Parse accepts the standard base64 form or the hexadecimal UAPI form.
func Parse(value string) ([Size]byte, error) {
	var key [Size]byte
	value = strings.TrimSpace(value)
	if value == "" {
		return key, errors.New("empty WireGuard key")
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		raw, err = hex.DecodeString(value)
	}
	if err != nil || len(raw) != Size {
		return key, fmt.Errorf("WireGuard key must be %d bytes in base64 or hexadecimal form", Size)
	}
	copy(key[:], raw)
	return key, nil
}

// Encode returns the standard WireGuard base64 representation.
func Encode(key [Size]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// Hex returns the WireGuard UAPI hexadecimal representation.
func Hex(key [Size]byte) string {
	return hex.EncodeToString(key[:])
}

// IsZero reports whether key is WireGuard's all-zero sentinel.
func IsZero(key [Size]byte) bool {
	var zero [Size]byte
	return key == zero
}

// GeneratePrivate creates a clamped X25519 private key.
func GeneratePrivate() ([Size]byte, error) {
	var key [Size]byte
	if _, err := rand.Read(key[:]); err != nil {
		return key, err
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key, nil
}

// GeneratePreShared creates a uniformly random preshared key.
func GeneratePreShared() ([Size]byte, error) {
	var key [Size]byte
	_, err := rand.Read(key[:])
	return key, err
}

// Public derives the public key for a private key.
func Public(private [Size]byte) ([Size]byte, error) {
	var public [Size]byte
	raw, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return public, err
	}
	copy(public[:], raw)
	return public, nil
}
