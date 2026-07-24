package uuid

import "testing"

func TestParseStringRejectsTrailingGarbage(t *testing.T) {
	if _, err := ParseString("00112233445566778899aabbccddeeffjunk"); err == nil {
		t.Fatal("UUID with trailing garbage was accepted")
	}
}
