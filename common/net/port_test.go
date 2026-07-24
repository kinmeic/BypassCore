package net

import "testing"

func TestPortRejectsZero(t *testing.T) {
	if _, err := PortFromInt(0); err == nil {
		t.Fatal("zero port was accepted")
	}
	if _, err := PortFromString("0"); err == nil {
		t.Fatal("zero port string was accepted")
	}
}
