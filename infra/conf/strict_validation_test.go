package conf

import (
	"encoding/json"
	"testing"
)

func TestNetworkListRejectsUnknownValue(t *testing.T) {
	var networks NetworkList
	if err := json.Unmarshal([]byte(`"tpc"`), &networks); err == nil {
		t.Fatal("unknown network was accepted")
	}
}

func TestRoutingRuleRejectsAmbiguousTarget(t *testing.T) {
	_, err := parseFieldRule(json.RawMessage(`{
		"inboundTag":["in"], "outboundTag":"direct", "balancerTag":"wan"
	}`))
	if err == nil {
		t.Fatal("rule with outboundTag and balancerTag was accepted")
	}
}

func TestLeastLoadRejectsMalformedSettings(t *testing.T) {
	badType := json.RawMessage(`"bad"`)
	rule := BalancingRule{
		Tag: "wan", Selectors: StringList{"wan"},
		Strategy: StrategyConfig{Type: "leastload", Settings: &badType},
	}
	if _, err := rule.Build(); err == nil {
		t.Fatal("malformed leastload settings were accepted")
	}

	badTolerance := json.RawMessage(`{"tolerance":1.5}`)
	rule.Strategy.Settings = &badTolerance
	if _, err := rule.Build(); err == nil {
		t.Fatal("out-of-range leastload tolerance was accepted")
	}
}

func TestPortListAcceptsMixedArray(t *testing.T) {
	var ports PortList
	if err := json.Unmarshal([]byte(`[80,"443,8000-8001"]`), &ports); err != nil {
		t.Fatal(err)
	}
	if len(ports.Range) != 3 {
		t.Fatalf("got %d ranges", len(ports.Range))
	}
}
