package outbound

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eugene/bypasscore/app/dialer"
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/common/wgkey"
	featoutbound "github.com/eugene/bypasscore/features/outbound"
)

type testDialer struct{ tag string }

func (*testDialer) Dial(context.Context, bcnet.Destination) (net.Conn, error) { return nil, nil }
func (d *testDialer) Tag() string                                             { return d.tag }

type closingTestDialer struct {
	testDialer
	closed *atomic.Int32
}

func (d *closingTestDialer) Close() error {
	d.closed.Add(1)
	return nil
}

type blockingCloseHandler struct {
	tag     string
	started chan struct{}
	release chan struct{}
}

type countingCloseHandler struct {
	tag    string
	closed atomic.Int32
}

func (*countingCloseHandler) Type() interface{} { return featoutbound.ManagerType() }
func (*countingCloseHandler) Start() error      { return nil }
func (h *countingCloseHandler) Close() error    { h.closed.Add(1); return nil }
func (h *countingCloseHandler) Tag() string     { return h.tag }

func (h *blockingCloseHandler) Type() interface{} { return featoutbound.ManagerType() }
func (*blockingCloseHandler) Start() error        { return nil }
func (h *blockingCloseHandler) Close() error {
	close(h.started)
	<-h.release
	return nil
}
func (h *blockingCloseHandler) Tag() string { return h.tag }

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
	m4 := NewManager(&Config{Outbounds: []*Outbound{{
		Tag: "bad-limit", Mode: ModeProxy,
		Upstream: &UpstreamConfig{Protocol: "socks", Server: "127.0.0.1:1080", Settings: map[string]any{"udpMaxPacketBytes": 1.5}},
	}}})
	if err := m4.Validate(); err == nil {
		t.Fatal("Validate should reject a non-integer UDP packet limit")
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
		{ModeWireGuard, "wireguard"},
	}
	for _, c := range cases {
		if got := c.m.String(); got != c.want {
			t.Errorf("Mode(%d).String() = %q, want %q", c.m, got, c.want)
		}
	}
}

func TestValidateWireGuard(t *testing.T) {
	private, err := wgkey.GeneratePrivate()
	if err != nil {
		t.Fatal(err)
	}
	public, err := wgkey.Public(private)
	if err != nil {
		t.Fatal(err)
	}
	peerPrivate, err := wgkey.GeneratePrivate()
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, err := wgkey.Public(peerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	config := &WireGuardConfig{
		SecretKey: wgkey.Encode(private),
		PublicKey: wgkey.Encode(public),
		Address:   []string{"10.0.0.2/32"},
		Peers: []*WireGuardPeerConfig{{
			PublicKey:  wgkey.Encode(peerPublic),
			Endpoint:   "vpn.example.com:51820",
			AllowedIPs: []string{"0.0.0.0/0"},
			KeepAlive:  25,
		}},
		MTU: 1420,
	}
	manager := NewManager(&Config{Outbounds: []*Outbound{{
		Tag: "wg", Mode: ModeWireGuard, WireGuard: config,
	}}})
	if err := manager.Validate(); err != nil {
		t.Fatalf("valid WireGuard config rejected: %v", err)
	}

	config.PublicKey = wgkey.Encode(peerPublic)
	if err := manager.Validate(); err == nil {
		t.Fatal("mismatched local public key was accepted")
	}

	config.PublicKey = ""
	if err := manager.Validate(); err == nil {
		t.Fatal("missing local public key was accepted")
	}

	config.PublicKey = wgkey.Encode(public)
	config.Peers[0].Endpoint = "vpn.example.com:0"
	if err := manager.Validate(); err == nil {
		t.Fatal("zero peer endpoint port was accepted")
	}

	config.Peers[0].Endpoint = ":51820"
	if err := manager.Validate(); err == nil {
		t.Fatal("empty peer endpoint host was accepted")
	}

	config.SecretKey = wgkey.Encode([wgkey.Size]byte{})
	if err := manager.Validate(); err == nil {
		t.Fatal("all-zero local secret key was accepted")
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

func TestValidateRejectsInvalidConfiguredEntries(t *testing.T) {
	m := NewManager(&Config{Outbounds: []*Outbound{
		nil,
		{Tag: "", Mode: ModeFreedom},
		{Tag: "direct", Mode: ModeFreedom},
	}})
	if err := m.Validate(); err == nil {
		t.Fatal("invalid configured outbound entries were silently ignored")
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

func TestManagerDialerFactoryIsPerHandlerAndConcurrent(t *testing.T) {
	var calls atomic.Int64
	SetDialerFactory(func(ob *Outbound) dialer.Dialer {
		calls.Add(1)
		return &testDialer{tag: ob.Tag}
	})
	m := NewManager(&Config{Outbounds: []*Outbound{{Tag: "direct", Mode: ModeFreedom}}})

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d := m.GetDialer("direct"); d == nil || d.Tag() != "direct" {
				t.Errorf("GetDialer returned %v", d)
			}
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("dialer factory calls=%d, want 1", got)
	}
}

func TestManagerCloseDoesNotBlockReaders(t *testing.T) {
	h := &blockingCloseHandler{tag: "slow", started: make(chan struct{}), release: make(chan struct{})}
	m := NewManager(nil)
	if err := m.AddHandler(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	<-h.started

	read := make(chan struct{})
	go func() {
		_ = m.GetHandler("slow")
		close(read)
	}()
	select {
	case <-read:
	case <-time.After(time.Second):
		t.Fatal("manager reader blocked behind slow handler Close")
	}
	close(h.release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if m.GetHandler("slow") != nil {
		t.Fatal("closed manager exposed a handler")
	}
}

func TestAddHandlerReplacementClosesOldHandler(t *testing.T) {
	m := NewManager(nil)
	old := &countingCloseHandler{tag: "same"}
	if err := m.AddHandler(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := m.AddHandler(context.Background(), &countingCloseHandler{tag: "same"}); err != nil {
		t.Fatal(err)
	}
	if old.closed.Load() != 1 {
		t.Fatalf("replaced handler close count=%d, want 1", old.closed.Load())
	}
}

func TestAddDescriptorReplacementClosesInitializedDialer(t *testing.T) {
	var closed atomic.Int32
	SetDialerFactory(func(ob *Outbound) dialer.Dialer {
		return &closingTestDialer{testDialer: testDialer{tag: ob.Tag}, closed: &closed}
	})
	m := NewManager(&Config{Outbounds: []*Outbound{{Tag: "same", Mode: ModeFreedom}}})
	if m.GetDialer("same") == nil {
		t.Fatal("failed to initialize old dialer")
	}
	m.Add(&Outbound{Tag: "same", Mode: ModeBlackhole})
	if got := closed.Load(); got != 1 {
		t.Fatalf("replaced descriptor dialer close count=%d, want 1", got)
	}
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
