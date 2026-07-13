package main

import (
	"os"
	"path/filepath"
	"testing"

	appoutbound "github.com/eugene/bypasscore/app/outbound"
	"github.com/eugene/bypasscore/app/router"
)

func TestValidateRoutingTargetsRejectsUnknownOutbound(t *testing.T) {
	ohm := appoutbound.NewManager(&appoutbound.Config{Outbounds: []*appoutbound.Outbound{
		{Tag: "direct", Mode: appoutbound.ModeFreedom},
	}})
	cfg := &router.Config{Rule: []*router.RoutingRule{{
		TargetTag: &router.RoutingRule_Tag{Tag: "typo"},
	}}}
	if err := validateRoutingTargets(cfg, ohm); err == nil {
		t.Fatal("unknown routed outbound must fail closed")
	}
}

func TestLoadConfigRejectsUnknownTopLevelField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"outbounds":[],"routng":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("unknown top-level field must be rejected")
	}
}
