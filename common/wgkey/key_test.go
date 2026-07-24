package wgkey

import (
	"strings"
	"testing"
)

func TestGenerateAndParse(t *testing.T) {
	private, err := GeneratePrivate()
	if err != nil {
		t.Fatal(err)
	}
	if private[0]&7 != 0 || private[31]&0x80 != 0 || private[31]&0x40 == 0 {
		t.Fatal("generated private key is not clamped")
	}
	encoded := Encode(private)
	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != private {
		t.Fatal("base64 round trip changed key")
	}
	public, err := Public(private)
	if err != nil {
		t.Fatal(err)
	}
	if public == ([Size]byte{}) {
		t.Fatal("derived public key is empty")
	}
}

func TestParseRejectsInvalidLength(t *testing.T) {
	if _, err := Parse("AQID"); err == nil {
		t.Fatal("short key was accepted")
	}
}

func TestParseHexThatIsAlsoValidBase64(t *testing.T) {
	value := strings.Repeat("01", Size)
	key, err := Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range key {
		if b != 1 {
			t.Fatalf("byte %d = %d, want 1", i, b)
		}
	}
}
