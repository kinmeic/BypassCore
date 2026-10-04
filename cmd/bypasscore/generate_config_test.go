package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConfigGeneratorProtectsCredentialsAndRejectsInvalidInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell generator")
	}
	validator, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "config with spaces.json")
	if err := os.WriteFile(output, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(input string) error {
		cmd := exec.Command("sh", "../../scripts/generate-config.sh", output)
		cmd.Env = append(os.Environ(), "BYPASSCORE_BIN="+validator)
		cmd.Stdin = strings.NewReader(input)
		result, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("generator output: %s", result)
		}
		return err
	}
	password := "tabs\tand\"quotes\\slash"
	if err := run("y\n\n01080\n\n2\n127.0.0.1:1081\ny\nuser\n" + password + "\nn\n"); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var config Config
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatal(err)
	}
	if config.Inbounds[0].Port != 1080 || !strings.Contains(string(payload), `tabs\u0009and\"quotes\\slash`) {
		t.Fatalf("port or password escaping failed: %s", payload)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions: %v, %v", info, err)
	}
	for _, input := range []string{"y\n\n\ntcp,udp\n", "y\n\n\n\n9\n"} {
		if run(input) == nil {
			t.Fatal("invalid input accepted")
		}
		current, err := os.ReadFile(output)
		if err != nil || string(current) != string(payload) {
			t.Fatal("invalid input overwrote existing config")
		}
	}
	leftovers, err := filepath.Glob(output + ".tmp.*")
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v, %v", leftovers, err)
	}
}
