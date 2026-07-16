package inbound

import (
	"fmt"
	"time"
)

const (
	defaultUDPMaxSessions            = 1024
	defaultUDPMaxSessionsPerSource   = 256
	defaultUDPSessionQueueBytes      = 64 * 1024
	defaultUDPSessionQueuePackets    = 64
	defaultUDPSessionIdleTimeout     = 2 * time.Minute
	defaultUDPSniffWait              = 25 * time.Millisecond
	defaultUDPSniffMaxPackets        = 4
	maximumUDPConfiguredSessions     = 65535
	maximumUDPConfiguredQueueBytes   = 16 * 1024 * 1024
	maximumUDPConfiguredQueuePackets = 4096
	maximumUDPConfiguredIdleTimeout  = 24 * time.Hour
)

type udpResourceLimits struct {
	maxSessions          int64
	maxSessionsPerSource int
	queueBytes           int64
	queuePackets         int
	idleTimeout          time.Duration
	sniffWait            time.Duration
	sniffMaxPackets      int
}

func udpResourceLimitsFromConfig(cfg *Config) (udpResourceLimits, error) {
	limits := udpResourceLimits{
		maxSessions:          defaultUDPMaxSessions,
		maxSessionsPerSource: defaultUDPMaxSessionsPerSource,
		queueBytes:           defaultUDPSessionQueueBytes,
		queuePackets:         defaultUDPSessionQueuePackets,
		idleTimeout:          defaultUDPSessionIdleTimeout,
		sniffWait:            defaultUDPSniffWait,
		sniffMaxPackets:      defaultUDPSniffMaxPackets,
	}
	if cfg == nil {
		return limits, fmt.Errorf("UDP tproxy: nil inbound config")
	}
	if cfg.UDPMaxSessions != 0 {
		if cfg.UDPMaxSessions < 1 || cfg.UDPMaxSessions > maximumUDPConfiguredSessions {
			return limits, fmt.Errorf("UDP tproxy: udpMaxSessions must be between 1 and %d", maximumUDPConfiguredSessions)
		}
		limits.maxSessions = int64(cfg.UDPMaxSessions)
	}
	if cfg.UDPMaxSessionsPerSource != 0 {
		if cfg.UDPMaxSessionsPerSource < 1 || int64(cfg.UDPMaxSessionsPerSource) > limits.maxSessions {
			return limits, fmt.Errorf("UDP tproxy: udpMaxSessionsPerSource must be between 1 and udpMaxSessions")
		}
		limits.maxSessionsPerSource = cfg.UDPMaxSessionsPerSource
	} else if int64(limits.maxSessionsPerSource) > limits.maxSessions {
		limits.maxSessionsPerSource = int(limits.maxSessions)
	}
	if cfg.UDPSessionQueueBytes != 0 {
		if cfg.UDPSessionQueueBytes < 512 || cfg.UDPSessionQueueBytes > maximumUDPConfiguredQueueBytes {
			return limits, fmt.Errorf("UDP tproxy: udpSessionQueueBytes must be between 512 and %d", maximumUDPConfiguredQueueBytes)
		}
		limits.queueBytes = int64(cfg.UDPSessionQueueBytes)
	}
	if cfg.UDPSessionQueuePackets != 0 {
		if cfg.UDPSessionQueuePackets < 1 || cfg.UDPSessionQueuePackets > maximumUDPConfiguredQueuePackets {
			return limits, fmt.Errorf("UDP tproxy: udpSessionQueuePackets must be between 1 and %d", maximumUDPConfiguredQueuePackets)
		}
		limits.queuePackets = cfg.UDPSessionQueuePackets
	}
	if cfg.UDPSessionIdleTimeoutSeconds != 0 {
		idle := time.Duration(cfg.UDPSessionIdleTimeoutSeconds) * time.Second
		if idle < time.Second || idle > maximumUDPConfiguredIdleTimeout {
			return limits, fmt.Errorf("UDP tproxy: udpSessionIdleTimeoutSeconds must be between 1 and %d", int(maximumUDPConfiguredIdleTimeout/time.Second))
		}
		limits.idleTimeout = idle
	}
	if cfg.UDPSniffWaitMs != 0 {
		if cfg.UDPSniffWaitMs < 1 || cfg.UDPSniffWaitMs > 1000 {
			return limits, fmt.Errorf("UDP tproxy: udpSniffWaitMs must be between 1 and 1000")
		}
		limits.sniffWait = time.Duration(cfg.UDPSniffWaitMs) * time.Millisecond
	}
	if cfg.UDPSniffMaxPackets != 0 {
		if cfg.UDPSniffMaxPackets < 1 || cfg.UDPSniffMaxPackets > 32 {
			return limits, fmt.Errorf("UDP tproxy: udpSniffMaxPackets must be between 1 and 32")
		}
		limits.sniffMaxPackets = cfg.UDPSniffMaxPackets
	}
	return limits, nil
}
