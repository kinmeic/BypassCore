//go:build linux && !android

package net

import (
	stdnet "net"
	"testing"
)

func TestFormatLittleEndianString(t *testing.T) {
	tests := []struct {
		ip   string
		port Port
		want string
	}{
		{"127.0.0.1", 8080, "0100007F:1F90"},
		{"2001:db8::1", 443, "B80D0120000000000000000001000000:01BB"},
	}
	for _, test := range tests {
		got, err := formatLittleEndianString(stdnet.ParseIP(test.ip), test.port)
		if err != nil {
			t.Fatalf("formatLittleEndianString(%q): %v", test.ip, err)
		}
		if got != test.want {
			t.Errorf("formatLittleEndianString(%q) = %q, want %q", test.ip, got, test.want)
		}
	}
}
