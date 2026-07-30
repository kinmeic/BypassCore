package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/eugene/bypasscore/common/errors"
)

// defaultServiceName is the service/init name used by install and uninstall
// unless overridden with -name (or BYPASSCORE_SERVICE_NAME on Windows).
const defaultServiceName = "bypasscore"

var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// serviceOptions carries the flags shared by the install and uninstall
// subcommands.
type serviceOptions struct {
	name      string
	configSrc string
	binSrc    string
	noCopyBin bool
	start     bool
	purge     bool
}

// runServiceCommand implements `bypasscore install` and `bypasscore uninstall`.
func runServiceCommand(command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	opts := &serviceOptions{}
	fs.StringVar(&opts.name, "name", defaultServiceName, "service name")
	fs.StringVar(&opts.configSrc, "config", "", "config file to install (copied to the system config path)")
	fs.StringVar(&opts.binSrc, "bin", "", "bypasscore binary to install (default: the current executable)")
	fs.BoolVar(&opts.noCopyBin, "no-copy-bin", false, "reference the binary in place instead of copying it to the system bin directory")
	fs.BoolVar(&opts.start, "start", true, "start the service after install")
	fs.BoolVar(&opts.purge, "purge", false, "uninstall: also remove the installed config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !serviceNamePattern.MatchString(opts.name) {
		return errors.New("invalid service name: ", opts.name)
	}
	switch command {
	case "install":
		return installService(opts)
	case "uninstall":
		return uninstallService(opts)
	default:
		return errors.New("unknown service command: ", command)
	}
}

// servicePlatform identifies the init system in use.
type servicePlatform int

const (
	platformSystemd servicePlatform = iota
	platformOpenWrt
	platformLaunchd
	platformWindows
)

func detectServicePlatform() (servicePlatform, error) {
	switch runtime.GOOS {
	case "windows":
		return platformWindows, nil
	case "darwin":
		return platformLaunchd, nil
	case "linux":
		if _, err := os.Stat("/etc/openwrt_release"); err == nil {
			return platformOpenWrt, nil
		}
		return platformSystemd, nil
	default:
		return 0, errors.New("install/uninstall is not supported on ", runtime.GOOS)
	}
}

// defaultServiceConfigPath is the config path the installed service runs with.
func defaultServiceConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(programDataDir(), defaultServiceName, "config.json")
	}
	return filepath.Join("/etc", defaultServiceName, "config.json")
}

func programDataDir() string {
	if dir := os.Getenv("ProgramData"); dir != "" {
		return dir
	}
	return `C:\ProgramData`
}

func defaultBinDir() string {
	switch runtime.GOOS {
	case "windows":
		if dir := os.Getenv("ProgramFiles"); dir != "" {
			return filepath.Join(dir, defaultServiceName)
		}
		return `C:\Program Files\bypasscore`
	case "darwin":
		return "/usr/local/bin"
	default:
		return "/usr/bin"
	}
}

func serviceConfigDir(name string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(programDataDir(), name)
	}
	return filepath.Join("/etc", name)
}

// serviceInstallPaths resolves the final binary and config paths the service
// unit will reference, and copies files into place when requested.
func serviceInstallPaths(opts *serviceOptions) (binPath, configPath string, err error) {
	binSrc := opts.binSrc
	if binSrc == "" {
		binSrc, err = os.Executable()
		if err != nil {
			return "", "", errors.New("locate current executable: ").Base(err)
		}
	}
	if binSrc, err = filepath.Abs(binSrc); err != nil {
		return "", "", err
	}
	if _, err := os.Stat(binSrc); err != nil {
		return "", "", errors.New("binary not found: ", binSrc)
	}
	binName := opts.name
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath = filepath.Join(defaultBinDir(), binName)
	if opts.noCopyBin || sameFilePath(binSrc, binPath) {
		binPath = binSrc
	} else if err := copyFile(binSrc, binPath, 0o755); err != nil {
		return "", "", errors.New("install binary to ", binPath, ": ").Base(err)
	}

	configPath = filepath.Join(serviceConfigDir(opts.name), "config.json")
	if opts.configSrc == "" {
		// Reuse a previously installed config when present (e.g. reinstall).
		if _, statErr := os.Stat(configPath); statErr != nil {
			return "", "", errors.New("no -config given and no installed config at ", configPath)
		}
	} else {
		configSrc, absErr := filepath.Abs(opts.configSrc)
		if absErr != nil {
			return "", "", absErr
		}
		// Fail early on an invalid config instead of installing a broken service.
		if _, loadErr := loadConfig(configSrc); loadErr != nil {
			return "", "", errors.New("invalid config: ").Base(loadErr)
		}
		if sameFilePath(configSrc, configPath) {
			configPath = configSrc
		} else if err := copyFile(configSrc, configPath, 0o600); err != nil {
			return "", "", errors.New("install config to ", configPath, ": ").Base(err)
		}
	}
	return binPath, configPath, nil
}

func installService(opts *serviceOptions) error {
	platform, err := detectServicePlatform()
	if err != nil {
		return err
	}
	binPath, configPath, err := serviceInstallPaths(opts)
	if err != nil {
		return err
	}
	switch platform {
	case platformSystemd:
		err = installSystemd(opts, binPath, configPath)
	case platformOpenWrt:
		err = installOpenWrt(opts, binPath, configPath)
	case platformLaunchd:
		err = installLaunchd(opts, binPath, configPath)
	case platformWindows:
		err = installWindows(opts, binPath, configPath)
	}
	if err != nil {
		return err
	}
	fmt.Printf("Service %q installed.\n  binary: %s\n  config: %s\n", opts.name, binPath, configPath)
	return nil
}

func uninstallService(opts *serviceOptions) error {
	platform, err := detectServicePlatform()
	if err != nil {
		return err
	}
	switch platform {
	case platformSystemd:
		err = uninstallSystemd(opts)
	case platformOpenWrt:
		err = uninstallOpenWrt(opts)
	case platformLaunchd:
		err = uninstallLaunchd(opts)
	case platformWindows:
		err = uninstallWindows(opts)
	}
	if err != nil {
		return err
	}
	if opts.purge {
		configPath := filepath.Join(serviceConfigDir(opts.name), "config.json")
		if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
			return errors.New("remove config ", configPath, ": ").Base(err)
		}
		fmt.Printf("Removed %s\n", configPath)
	} else {
		fmt.Printf("Installed config kept at %s (use -purge to remove it)\n", filepath.Join(serviceConfigDir(opts.name), "config.json"))
	}
	fmt.Printf("Service %q uninstalled.\n", opts.name)
	return nil
}

// --- systemd (Linux) ---

func systemdUnitPath(name string) string {
	return filepath.Join("/etc/systemd/system", name+".service")
}

func renderSystemdUnit(name, binPath, configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=BypassCore routing engine (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s -config %s -run
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, name, binPath, configPath)
}

func installSystemd(opts *serviceOptions, binPath, configPath string) error {
	unitPath := systemdUnitPath(opts.name)
	if err := os.WriteFile(unitPath, []byte(renderSystemdUnit(opts.name, binPath, configPath)), 0o644); err != nil {
		return errors.New("write unit ", unitPath, ": ").Base(err)
	}
	if _, err := runCommand("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := runCommand("systemctl", "enable", opts.name+".service"); err != nil {
		return err
	}
	if opts.start {
		if _, err := runCommand("systemctl", "restart", opts.name+".service"); err != nil {
			return err
		}
	}
	return nil
}

func uninstallSystemd(opts *serviceOptions) error {
	unit := opts.name + ".service"
	_, _ = runCommand("systemctl", "stop", unit)
	_, _ = runCommand("systemctl", "disable", unit)
	unitPath := systemdUnitPath(opts.name)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return errors.New("remove unit ", unitPath, ": ").Base(err)
	}
	if _, err := runCommand("systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, _ = runCommand("systemctl", "reset-failed", unit)
	return nil
}

// --- procd (OpenWrt) ---

func openWrtInitPath(name string) string {
	return filepath.Join("/etc/init.d", name)
}

func renderOpenWrtInit(name, binPath, configPath string) string {
	return fmt.Sprintf(`#!/bin/sh /etc/rc.common

# BypassCore routing engine (%s), installed by "bypasscore install".
START=99
STOP=10
USE_PROCD=1

PROG=%s
CONF=%s

start_service() {
	procd_open_instance %s
	procd_set_param command "$PROG" -config "$CONF" -run
	procd_set_param respawn 3600 5 5
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}
`, name, binPath, configPath, name)
}

func installOpenWrt(opts *serviceOptions, binPath, configPath string) error {
	initPath := openWrtInitPath(opts.name)
	if err := os.WriteFile(initPath, []byte(renderOpenWrtInit(opts.name, binPath, configPath)), 0o755); err != nil {
		return errors.New("write init script ", initPath, ": ").Base(err)
	}
	if _, err := runCommand(initPath, "enable"); err != nil {
		return err
	}
	if opts.start {
		if _, err := runCommand(initPath, "restart"); err != nil {
			return err
		}
	}
	return nil
}

func uninstallOpenWrt(opts *serviceOptions) error {
	initPath := openWrtInitPath(opts.name)
	_, _ = runCommand(initPath, "stop")
	_, _ = runCommand(initPath, "disable")
	if err := os.Remove(initPath); err != nil && !os.IsNotExist(err) {
		return errors.New("remove init script ", initPath, ": ").Base(err)
	}
	return nil
}

// --- launchd (macOS) ---

func launchdLabel(name string) string {
	sanitized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, name)
	return "com.bypasscore." + sanitized
}

func launchdPlistPath(label string) string {
	return filepath.Join("/Library/LaunchDaemons", label+".plist")
}

func renderLaunchdPlist(label, binPath, configPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>-config</string>
		<string>%s</string>
		<string>-run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>StandardOutPath</key>
	<string>/var/log/bypasscore.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/bypasscore.err</string>
</dict>
</plist>
`, label, binPath, configPath)
}

func installLaunchd(opts *serviceOptions, binPath, configPath string) error {
	label := launchdLabel(opts.name)
	plistPath := launchdPlistPath(label)
	if err := os.WriteFile(plistPath, []byte(renderLaunchdPlist(label, binPath, configPath)), 0o644); err != nil {
		return errors.New("write plist ", plistPath, ": ").Base(err)
	}
	// Unload any previous install, then load the new plist.
	_, _ = runCommand("launchctl", "bootout", "system/"+label)
	if _, err := runCommand("launchctl", "bootstrap", "system", plistPath); err != nil {
		// Fallback for older macOS without bootstrap.
		if _, loadErr := runCommand("launchctl", "load", "-w", plistPath); loadErr != nil {
			return err
		}
	}
	return nil
}

func uninstallLaunchd(opts *serviceOptions) error {
	label := launchdLabel(opts.name)
	plistPath := launchdPlistPath(label)
	if _, err := runCommand("launchctl", "bootout", "system/"+label); err != nil {
		_, _ = runCommand("launchctl", "unload", "-w", plistPath)
	}
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return errors.New("remove plist ", plistPath, ": ").Base(err)
	}
	return nil
}

// --- Windows Service Control Manager ---

func installWindows(opts *serviceOptions, binPath, configPath string) error {
	binPathWithArgs := fmt.Sprintf(`"%s" -config "%s" -run`, binPath, configPath)
	if _, err := runCommand("sc.exe", "create", opts.name,
		"binPath=", binPathWithArgs,
		"start=", "auto",
		"DisplayName=", "BypassCore routing engine ("+opts.name+")",
	); err != nil {
		return err
	}
	if _, err := runCommand("sc.exe", "description", opts.name,
		"BypassCore routing engine: inbound listeners, routing and outbound dispatch"); err != nil {
		return err
	}
	// Restart automatically on failure: 5s / 10s / 30s, reset counter daily.
	if _, err := runCommand("sc.exe", "failure", opts.name,
		"reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000"); err != nil {
		return err
	}
	if opts.start {
		if _, err := runCommand("sc.exe", "start", opts.name); err != nil {
			return err
		}
	}
	return nil
}

func uninstallWindows(opts *serviceOptions) error {
	_, _ = runCommand("sc.exe", "stop", opts.name)
	if _, err := runCommand("sc.exe", "delete", opts.name); err != nil {
		return err
	}
	return nil
}

// --- shared helpers ---

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func sameFilePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return false
	}
	return absA == absB
}

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		output := strings.TrimSpace(out.String())
		if output != "" {
			return output, errors.New(name, " ", strings.Join(args, " "), ": ", output)
		}
		return output, errors.New(name, " ", strings.Join(args, " "), ": ").Base(err)
	}
	return out.String(), nil
}
