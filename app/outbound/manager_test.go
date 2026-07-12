package outbound

import (
	"testing"
)

func TestNewManager(t *testing.T) {
	cfg := &Config{Outbounds: []*Outbound{
		{Tag: "direct", Mode: ModeFreedom},
		{Tag: "wan1", Mode: ModeFreedom, Bind: &BindConfig{Interface: "en0", LocalIP: "192.168.1.2"}},
		{Tag: "wan2", Mode: ModeFreedom, Bind: &BindConfig{Interface: "en1", LocalIP: "192.168.2.2"}},
		{Tag: "block", Mode: ModeBlackhole},
	}}
	m := NewManager(cfg)

	if got := m.GetOutbound("wan1"); got == nil || got.Tag != "wan1" {
		t.Fatalf("GetOutbound(wan1) = %v, want wan1", got)
	}
	if got := m.GetOutbound("nope"); got != nil {
		t.Fatalf("GetOutbound(missing) = %v, want nil", got)
	}
	// Default is the first registered.
	if got := m.GetDefaultHandler(); got == nil || got.Tag() != "direct" {
		t.Fatalf("default handler = %v, want direct", got)
	}
	// List preserves order.
	list := m.List()
	if len(list) != 4 || list[0].Tag != "direct" || list[3].Tag != "block" {
		t.Fatalf("List order wrong: %v", list)
	}
}

func TestManagerSelect(t *testing.T) {
	m := NewManager(&Config{Outbounds: []*Outbound{
		{Tag: "direct", Mode: ModeFreedom},
		{Tag: "wan1", Mode: ModeFreedom},
		{Tag: "wan2", Mode: ModeFreedom},
		{Tag: "proxy", Mode: ModeProxy, Upstream: &UpstreamConfig{Protocol: "trojan", Server: "x:443"}},
	}})

	// Prefix "wan" selects wan1 and wan2.
	got := m.Select([]string{"wan"})
	if len(got) != 2 || got[0] != "wan1" || got[1] != "wan2" {
		t.Fatalf(`Select(["wan"]) = %v, want [wan1 wan2]`, got)
	}
	// Exact tag matches itself.
	got = m.Select([]string{"proxy"})
	if len(got) != 1 || got[0] != "proxy" {
		t.Fatalf(`Select(["proxy"]) = %v, want [proxy]`, got)
	}
	// Multiple selectors union (order preserved, dedup).
	got = m.Select([]string{"wan", "direct"})
	if len(got) != 3 || got[0] != "direct" || got[1] != "wan1" || got[2] != "wan2" {
		t.Fatalf(`Select(["wan","direct"]) = %v, want [direct wan1 wan2]`, got)
	}
	// Empty selector returns all.
	got = m.Select(nil)
	if len(got) != 4 {
		t.Fatalf("Select(nil) = %v, want all 4", got)
	}
	// Non-matching selector returns empty.
	got = m.Select([]string{"zzz"})
	if len(got) != 0 {
		t.Fatalf(`Select(["zzz"]) = %v, want []`, got)
	}
}

func TestValidateProxyRequiresUpstream(t *testing.T) {
	m := NewManager(&Config{Outbounds: []*Outbound{
		{Tag: "bad", Mode: ModeProxy}, // missing upstream
	}})
	if err := m.Validate(); err == nil {
		t.Fatal("Validate should reject proxy outbound without upstream")
	}

	m2 := NewManager(&Config{Outbounds: []*Outbound{
		{Tag: "ok", Mode: ModeProxy, Upstream: &UpstreamConfig{Protocol: "trojan", Server: "x:443"}},
	}})
	if err := m2.Validate(); err != nil {
		t.Fatalf("Validate should pass: %v", err)
	}
}

func TestModeString(t *testing.T) {
	cases := []struct {
		m    Mode
		want string
	}{
		{ModeFreedom, "freedom"},
		{ModeBlackhole, "blackhole"},
		{ModeProxy, "proxy"},
	}
	for _, c := range cases {
		if got := c.m.String(); got != c.want {
			t.Errorf("Mode(%d).String() = %q, want %q", c.m, got, c.want)
		}
	}
}
