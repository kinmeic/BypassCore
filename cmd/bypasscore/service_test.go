package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCopyFileReplacesExistingFileWithRequestedMode(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "source"), filepath.Join(dir, "installed")
	if err := os.WriteFile(src, []byte("secret config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old config"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("installed config mode = %o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(dst)
	if err != nil || string(data) != "secret config" {
		t.Fatalf("copied data=%q err=%v", data, err)
	}
	// Copying aliases of the same inode must not destroy the source contents.
	if err := copyFile(src, src, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(src)
	if err != nil || string(data) != "secret config" {
		t.Fatalf("source contents=%q err=%v", data, err)
	}
}

func TestServiceNameValidation(t *testing.T) {
	valid := []string{"bypasscore", "bypass-core", "bypass_core", "core.service", "bypass2"}
	for _, name := range valid {
		if !serviceNamePattern.MatchString(name) {
			t.Errorf("valid service name rejected: %q", name)
		}
	}
	invalid := []string{"", "-lead", ".lead", "has space", "semi;colon", "a/b", "$(evil)"}
	for _, name := range invalid {
		if serviceNamePattern.MatchString(name) {
			t.Errorf("invalid service name accepted: %q", name)
		}
	}
}

func TestRenderSystemdUnit(t *testing.T) {
	unit := renderSystemdUnit("bypasscore", "/usr/bin/bypasscore", "/etc/bypasscore/config.json")
	for _, want := range []string{
		"[Unit]", "[Service]", "[Install]",
		`ExecStart="/usr/bin/bypasscore" -config "/etc/bypasscore/config.json" -run`,
		"Restart=on-failure",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("systemd unit missing %q:\n%s", want, unit)
		}
	}
}

func TestRenderOpenWrtInit(t *testing.T) {
	script := renderOpenWrtInit("bypasscore", "/usr/bin/bypasscore", "/etc/bypasscore/config.json")
	for _, want := range []string{
		"#!/bin/sh /etc/rc.common",
		"USE_PROCD=1",
		"START=99",
		`procd_set_param command "$PROG" -config "$CONF" -run`,
		"procd_set_param respawn",
		"PROG='/usr/bin/bypasscore'",
		"CONF='/etc/bypasscore/config.json'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("procd init script missing %q:\n%s", want, script)
		}
	}
}

func TestRenderLaunchdPlist(t *testing.T) {
	plist := renderLaunchdPlist("com.bypasscore.bypasscore", "/usr/local/bin/bypasscore", "/etc/bypasscore/config.json")
	for _, want := range []string{
		"<key>Label</key>",
		"<string>com.bypasscore.bypasscore</string>",
		"<string>/usr/local/bin/bypasscore</string>",
		"<string>-config</string>",
		"<string>/etc/bypasscore/config.json</string>",
		"<string>-run</string>",
		"<key>RunAtLoad</key>",
		"<key>KeepAlive</key>",
	} {
		if !strings.Contains(plist, want) {
			t.Errorf("launchd plist missing %q:\n%s", want, plist)
		}
	}
}

func TestLaunchdLabelSanitizesName(t *testing.T) {
	if got := launchdLabel("My Service"); got != "com.bypasscore.my-service" {
		t.Fatalf("unexpected label: %s", got)
	}
	if got := launchdLabel("bypasscore"); got != "com.bypasscore.bypasscore" {
		t.Fatalf("unexpected label: %s", got)
	}
}

func TestSameFilePath(t *testing.T) {
	if !sameFilePath("/etc/bypasscore/config.json", "/etc//bypasscore/config.json") {
		t.Fatal("equivalent paths must compare equal")
	}
	if sameFilePath("/etc/a.json", "/etc/b.json") {
		t.Fatal("different paths must not compare equal")
	}
}

func TestServiceRenderEscapesPaths(t *testing.T) {
	path := `/opt/core with spaces/%h/$HOME/'"&<>`
	unit := renderSystemdUnit("core", path, path)
	if !strings.Contains(unit, `"/opt/core with spaces/%%h/$HOME/'\"&<>"`) {
		t.Fatalf("systemd path not escaped: %s", unit)
	}
	if !strings.Contains(unit, `-config "/opt/core with spaces/%%h/$$HOME/'\"&<>"`) {
		t.Fatalf("systemd config environment expansion not escaped: %s", unit)
	}
	script := renderOpenWrtInit("core", path, path)
	if !strings.Contains(script, `PROG='/opt/core with spaces/%h/$HOME/'\''"&<>'`) {
		t.Fatalf("shell path not quoted: %s", script)
	}
	plist := renderLaunchdPlist("core", path, path)
	if !strings.Contains(plist, `&amp;&lt;&gt;`) {
		t.Fatalf("XML path not escaped: %s", plist)
	}
}
