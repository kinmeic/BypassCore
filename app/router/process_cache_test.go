package router

import (
	"errors"
	"sync/atomic"
	"testing"
)

func TestProcessLookupCacheCachesSuccessAndFailure(t *testing.T) {
	originalFinder := findProcess
	originalCache := processCache
	defer func() { findProcess = originalFinder; processCache = originalCache }()
	processCache = newProcessLookupCache()
	var calls atomic.Int32
	findProcess = func(_, _ string, sourcePort uint16, _ string, _ uint16) (int, string, string, error) {
		calls.Add(1)
		if sourcePort == 2 {
			return 0, "", "", errors.New("missing")
		}
		return 10, "curl", "/usr/bin/curl", nil
	}
	for i := 0; i < 2; i++ {
		pid, name, _, err := cachedFindProcess("tcp", "127.0.0.1", 1, "127.0.0.1", 80)
		if err != nil || pid != 10 || name != "curl" {
			t.Fatalf("lookup pid=%d name=%q err=%v", pid, name, err)
		}
		if _, _, _, err := cachedFindProcess("tcp", "127.0.0.1", 2, "127.0.0.1", 80); err == nil {
			t.Fatal("negative process lookup lost error")
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("process finder calls=%d, want one success and one failure", got)
	}
}

func TestProcessCacheFlightKeyPreservesAllPortValues(t *testing.T) {
	base := processCacheKey{network: "tcp", sourceIP: "127.0.0.1", destIP: "127.0.0.1", destPort: 80}
	first := base
	first.sourcePort = 0xd800
	second := base
	second.sourcePort = 0xd801
	if processCacheFlightKey(first) == processCacheFlightKey(second) {
		t.Fatal("distinct high ports produced the same singleflight key")
	}
}
