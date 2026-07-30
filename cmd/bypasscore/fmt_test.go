package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFormatConfigCanonicalizesWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	messy := "{  \"a\":1,\n\"b\":[1,   2],\t\"c\": {\"d\":true}\n}"
	if err := os.WriteFile(path, []byte(messy), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := formatConfig(path, false, &out); err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"a\": 1,\n  \"b\": [\n    1,\n    2\n  ],\n  \"c\": {\n    \"d\": true\n  }\n}\n"
	if out.String() != want {
		t.Fatalf("unexpected formatted output:\n%s", out.String())
	}
	// Stdout mode must not modify the file on disk.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != messy {
		t.Fatal("stdout mode modified the config file")
	}
}

func TestFormatConfigWriteInPlacePreservesMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := formatConfig(path, true, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{\n  \"a\": 1\n}\n" {
		t.Fatalf("unexpected in-place result: %q", raw)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permission not preserved: %v", info.Mode().Perm())
	}
}

func TestFormatConfigRejectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"a":`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := formatConfig(path, false, &bytes.Buffer{}); err == nil {
		t.Fatal("invalid JSON must be rejected")
	}
}

func TestFormatConfigRejectsDuplicateKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"a":1,"a":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := formatConfig(path, false, &bytes.Buffer{}); err == nil {
		t.Fatal("duplicate keys must be rejected")
	}
}
