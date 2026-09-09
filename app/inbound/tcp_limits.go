package inbound

import (
	"fmt"
	"time"

	"github.com/eugene/bypasscore/transport"
)

const maximumTCPConfiguredIdleTimeout = 24 * time.Hour

// tcpIdleTimeoutFromConfig resolves the TCP tunnel idle timeout. Zero means
// the shared default; a negative value disables eviction and is represented
// as a zero duration, which BridgeWithIdleTimeout treats as "no deadline".
func tcpIdleTimeoutFromConfig(cfg *Config) (time.Duration, error) {
	if cfg == nil {
		return 0, fmt.Errorf("inbound: nil config")
	}
	if cfg.TCPIdleTimeoutSeconds == 0 {
		return transport.DefaultConnIdleTimeout, nil
	}
	if cfg.TCPIdleTimeoutSeconds < 0 {
		return 0, nil
	}
	idle := time.Duration(cfg.TCPIdleTimeoutSeconds) * time.Second
	if idle > maximumTCPConfiguredIdleTimeout {
		return 0, fmt.Errorf("inbound: tcpIdleTimeoutSeconds must be between 1 and %d, or negative to disable", int(maximumTCPConfiguredIdleTimeout/time.Second))
	}
	return idle, nil
}
