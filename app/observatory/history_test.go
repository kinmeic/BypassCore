package observatory

import (
	"testing"
	"time"
)

func TestProbeHistoryProducesLeastLoadStatistics(t *testing.T) {
	history := new(probeHistory)
	history.add(10 * time.Millisecond)
	history.add(20 * time.Millisecond)
	history.add(-time.Nanosecond)
	stats := history.stats()
	if stats.All != 3 || stats.Fail != 1 {
		t.Fatalf("counts all=%d fail=%d", stats.All, stats.Fail)
	}
	if stats.Average != int64(15*time.Millisecond) || stats.Deviation != int64(5*time.Millisecond) {
		t.Fatalf("average=%s deviation=%s", time.Duration(stats.Average), time.Duration(stats.Deviation))
	}
}
