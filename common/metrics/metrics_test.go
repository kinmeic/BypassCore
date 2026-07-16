package metrics

import (
	"bytes"
	"strings"
	"testing"
)

func TestRegistryPrometheusOutput(t *testing.T) {
	ResetForTest()
	Inc("bypasscore_test_total", "transport", "udp", "inbound", "dns")
	Add("bypasscore_test_total", 2, "inbound", "dns", "transport", "udp")
	Set("bypasscore_active", 4)
	var output bytes.Buffer
	if err := WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, `bypasscore_test_total{inbound="dns",transport="udp"} 3`) ||
		!strings.Contains(text, "bypasscore_active 4") {
		t.Fatalf("unexpected metrics:\n%s", text)
	}
}

func TestRetainLabelValues(t *testing.T) {
	ResetForTest()
	Inc("connections_total", "outbound", "old", "result", "success")
	Inc("connections_total", "outbound", "current", "result", "success")
	RetainLabelValues(map[string]map[string]struct{}{"outbound": {"current": {}}})
	Inc("connections_total", "outbound", "old", "result", "success")
	samples := Snapshot()
	if len(samples) != 1 || !strings.Contains(samples[0].Labels, `outbound="current"`) {
		t.Fatalf("unexpected retained samples: %#v", samples)
	}
}
