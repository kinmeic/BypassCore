package inbound

import (
	"testing"
	"time"
)

func TestUDPResourceLimitsDefaults(t *testing.T) {
	limits, err := udpResourceLimitsFromConfig(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	if limits.maxSessions != 1024 || limits.maxSessionsPerSource != 256 ||
		limits.queueBytes != 64*1024 || limits.queuePackets != 64 ||
		limits.idleTimeout != 2*time.Minute {
		t.Fatalf("unexpected UDP defaults: %+v", limits)
	}
}

func TestUDPResourceLimitsOverrides(t *testing.T) {
	limits, err := udpResourceLimitsFromConfig(&Config{
		UDPMaxSessions:               128,
		UDPMaxSessionsPerSource:      32,
		UDPSessionQueueBytes:         8192,
		UDPSessionQueuePackets:       8,
		UDPSessionIdleTimeoutSeconds: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if limits.maxSessions != 128 || limits.maxSessionsPerSource != 32 ||
		limits.queueBytes != 8192 || limits.queuePackets != 8 || limits.idleTimeout != 30*time.Second {
		t.Fatalf("unexpected UDP overrides: %+v", limits)
	}
}

func TestUDPResourceLimitsRejectUnsafeValues(t *testing.T) {
	tests := []Config{
		{UDPMaxSessions: -1},
		{UDPMaxSessions: 2, UDPMaxSessionsPerSource: 3},
		{UDPSessionQueueBytes: 511},
		{UDPSessionQueuePackets: 4097},
		{UDPSessionIdleTimeoutSeconds: 86401},
	}
	for _, cfg := range tests {
		if _, err := udpResourceLimitsFromConfig(&cfg); err == nil {
			t.Fatalf("unsafe UDP limits accepted: %+v", cfg)
		}
	}
}
