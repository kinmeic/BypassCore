package outbound

import (
	"context"
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
	if err := m2.Validate(); err == nil {
		t.Fatal("Validate should reject unsupported proxy protocol")
	}
	m3 := NewManager(&Config{Outbounds: []*Outbound{
		{Tag: "ok", Mode: ModeProxy, Upstream: &UpstreamConfig{Protocol: "socks", Server: "127.0.0.1:1080"}},
	}})
	if err := m3.Validate(); err != nil {
		t.Fatalf("Validate should accept SOCKS: %v", err)
	}
}

func TestValidateRejectsDuplicateTags(t *testing.T) {
	m := NewManager(&Config{Outbounds: []*Outbound{
		{Tag: "direct", Mode: ModeFreedom},
		{Tag: "direct", Mode: ModeBlackhole},
	}})
	if err := m.Validate(); err == nil {
		t.Fatal("duplicate outbound tags must be rejected")
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

// TestAdd_IgnoresNilAndEmptyTag documents that Add silently drops nil outbounds
// and outbounds without a tag (per the guard at the top of Add).
func TestAdd_IgnoresNilAndEmptyTag(t *testing.T) {
	m := NewManager(nil)
	m.Add(nil)
	m.Add(&Outbound{Tag: ""})
	m.Add(&Outbound{Tag: "direct"})
	if got := len(m.handlers); got != 1 {
		t.Fatalf("after nil/empty adds, handlers=%d want 1", got)
	}
	if m.GetOutbound("direct") == nil {
		t.Fatal("direct should be registered")
	}
}

// TestAdd_OverwritesSameTag locks the documented behavior: re-adding a tag
// replaces the descriptor but keeps its position in order (first registration).
func TestAdd_OverwritesSameTag(t *testing.T) {
	m := NewManager(&Config{Outbounds: []*Outbound{
		{Tag: "a", Mode: ModeFreedom},
		{Tag: "b", Mode: ModeFreedom},
	}})
	// Re-add "a" with a different mode; order must NOT change.
	m.Add(&Outbound{Tag: "a", Mode: ModeBlackhole})

	list := m.List()
	if len(list) != 2 || list[0].Tag != "a" || list[1].Tag != "b" {
		t.Fatalf("order changed after re-add: %v", list)
	}
	if got := m.GetOutbound("a").Mode; got != ModeBlackhole {
		t.Fatalf("descriptor not updated: mode=%v want blackhole", got)
	}
}

// TestSelect_BarePrefixSemantics locks the documented (if surprising) behavior
// that Select uses a bare string prefix: "wan" matches "wanted". This is a
// known design trade-off for wan1/wan2 grouping; the test prevents accidental
// semantic changes. See AUDIT.md P1-1.
func TestSelect_BarePrefixSemantics(t *testing.T) {
	m := NewManager(&Config{Outbounds: []*Outbound{
		{Tag: "wan1", Mode: ModeFreedom},
		{Tag: "wan2", Mode: ModeFreedom},
		{Tag: "wanted", Mode: ModeFreedom}, // unintentionally shares "wan" prefix
	}})
	got := m.Select([]string{"wan"})
	// "wanted" IS included because matchSelector is a bare HasPrefix.
	want := []string{"wan1", "wan2", "wanted"}
	if len(got) != len(want) {
		t.Fatalf(`Select(["wan"]) = %v, want %v`, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf(`Select(["wan"])[%d] = %q, want %q`, i, got[i], want[i])
		}
	}
}

// TestSelect_DedupPreservesOrder verifies that multiple selectors matching the
// same tag do not duplicate it, and that the original registration order is
// preserved in the output.
func TestSelect_DedupPreservesOrder(t *testing.T) {
	m := NewManager(&Config{Outbounds: []*Outbound{
		{Tag: "proxy-hk", Mode: ModeProxy, Upstream: &UpstreamConfig{Protocol: "trojan", Server: "x:443"}},
		{Tag: "proxy-jp", Mode: ModeProxy, Upstream: &UpstreamConfig{Protocol: "trojan", Server: "y:443"}},
		{Tag: "direct", Mode: ModeFreedom},
	}})
	// Both "proxy" and "proxy-hk" match "proxy-hk"; it must appear only once.
	got := m.Select([]string{"proxy", "proxy-hk"})
	seen := map[string]int{}
	for _, tag := range got {
		seen[tag]++
	}
	if seen["proxy-hk"] != 1 {
		t.Errorf("proxy-hk appeared %d times, want 1 (got=%v)", seen["proxy-hk"], got)
	}
	// Registration order preserved: proxy-hk before proxy-jp.
	if len(got) >= 2 && got[0] != "proxy-hk" {
		t.Errorf("first selected = %q, want proxy-hk (registration order)", got[0])
	}
}

// TestValidate_NoOutbound and TestValidate_ProxyRequiresServer cover the
// validation gate used by the CLI before building the router.
func TestValidate_NoOutbound(t *testing.T) {
	m := NewManager(nil)
	if err := m.Validate(); err == nil {
		t.Fatal("Validate on empty manager must error")
	}
}

func TestValidate_ProxyRequiresServer(t *testing.T) {
	// proxy with empty server string is rejected.
	m := NewManager(&Config{Outbounds: []*Outbound{
		{Tag: "bad", Mode: ModeProxy, Upstream: &UpstreamConfig{Protocol: "trojan", Server: ""}},
	}})
	if err := m.Validate(); err == nil {
		t.Fatal("Validate must reject proxy with empty server")
	}
}

// TestAddHandler_AndRemoveHandler exercise the runtime handler API used by
// callers building a Manager incrementally.
func TestAddHandler_AndRemoveHandler(t *testing.T) {
	m := NewManager(&Config{Outbounds: []*Outbound{{Tag: "direct", Mode: ModeFreedom}}})

	if err := m.AddHandler(context.Background(), nil); err == nil {
		t.Error("AddHandler(nil) must error")
	}

	// Add an external handler; it becomes reachable via GetOutbound.
	if err := m.AddHandler(context.Background(), &handler{ob: &Outbound{Tag: "ext", Mode: ModeFreedom}}); err != nil {
		t.Fatalf("AddHandler: %v", err)
	}
	if got := m.GetOutbound("ext"); got == nil || got.Tag != "ext" {
		t.Fatalf("ext not reachable after AddHandler: %v", got)
	}
	// order should now be [direct, ext].
	list := m.List()
	if len(list) != 2 || list[1].Tag != "ext" {
		t.Fatalf("order wrong after AddHandler: %v", list)
	}

	// Remove a missing tag.
	if err := m.RemoveHandler(context.Background(), "nope"); err == nil {
		t.Error("RemoveHandler(missing) must error")
	}
	// Remove "direct" — the default; the slice element must be gone.
	if err := m.RemoveHandler(context.Background(), "direct"); err != nil {
		t.Fatalf("RemoveHandler(direct): %v", err)
	}
	if m.GetOutbound("direct") != nil {
		t.Fatal("direct still present after RemoveHandler")
	}
	// "ext" is now the first (default).
	if got := m.GetDefaultHandler(); got == nil || got.Tag() != "ext" {
		t.Fatalf("default after remove = %v, want ext", got)
	}
}

// TestRemoveHandler_OrderConsistency removes a middle element and verifies the
// order slice has no stale entries.
func TestRemoveHandler_OrderConsistency(t *testing.T) {
	m := NewManager(&Config{Outbounds: []*Outbound{
		{Tag: "a", Mode: ModeFreedom},
		{Tag: "b", Mode: ModeFreedom},
		{Tag: "c", Mode: ModeFreedom},
	}})
	if err := m.RemoveHandler(context.Background(), "b"); err != nil {
		t.Fatalf("RemoveHandler: %v", err)
	}
	if got := m.allTagsLocked(); len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("order after removing middle = %v, want [a c]", got)
	}
}

// TestGetHandler_NilForMissing documents GetHandler returns nil (not an error).
func TestGetHandler_NilForMissing(t *testing.T) {
	m := NewManager(nil)
	if h := m.GetHandler("anything"); h != nil {
		t.Fatalf("GetHandler on empty manager = %v, want nil", h)
	}
}

// TestManager_ConcurrentReadWrite is a regression test for the concurrency
// safety added in response to AUDIT.md P2-1: the observatory probes via Select
// from a background goroutine while the router/CLI may AddHandler/RemoveHandler.
// Previously the Manager's map/slice were accessed without a lock.
func TestManager_ConcurrentReadWrite(t *testing.T) {
	t.Parallel()
	m := NewManager(&Config{Outbounds: []*Outbound{
		{Tag: "direct", Mode: ModeFreedom},
		{Tag: "wan1", Mode: ModeFreedom},
		{Tag: "wan2", Mode: ModeFreedom},
	}})
	done := make(chan struct{})
	// Reader goroutine: Select + List + GetOutbound in a tight loop.
	go func() {
		defer close(done)
		for i := 0; i < 3000; i++ {
			_ = m.Select([]string{"wan"})
			_ = m.List()
			_ = m.GetOutbound("wan1")
			_ = m.GetDefaultHandler()
		}
	}()
	// Writer goroutine: churn the table.
	for i := 0; i < 1000; i++ {
		tag := "dyn" + itoa(i%50)
		_ = m.AddHandler(context.Background(), &handler{ob: &Outbound{Tag: tag, Mode: ModeFreedom}})
		if i%7 == 0 {
			_ = m.RemoveHandler(context.Background(), tag)
		}
	}
	<-done
}

// itoa avoids importing strconv just for the loop above.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
