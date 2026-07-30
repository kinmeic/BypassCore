//go:build !windows

package main

// runAsPlatformService is a no-op outside Windows: systemd/procd/launchd run
// the binary as a plain foreground process with signal-based shutdown.
func runAsPlatformService() (bool, error) {
	return false, nil
}
