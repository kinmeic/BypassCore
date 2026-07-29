package outbound

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/eugene/bypasscore/app/dialer"
	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/common/wgkey"
	featoutbound "github.com/eugene/bypasscore/features/outbound"
)

// Manager is a config-driven outbound.Manager. It is backed by the Outbound
// descriptor table and also implements HandlerSelector so the router's balancer
// can resolve selector prefixes to concrete tags.
//
// All methods are safe for concurrent use: reads take a read lock and writes
// (Add/AddHandler/RemoveHandler) take a write lock. This matters because the
// observatory probes outbounds via Select from a background goroutine while the
// router/CLI may mutate the table at runtime.
type Manager struct {
	// mu guards handlers and order.
	mu sync.RWMutex
	// handlers maps tag -> wrapped descriptor.
	handlers map[string]*handler
	// order preserves insertion order so the first registered outbound is the
	// default.
	order         []string
	duplicateTags map[string]struct{}
	configErrors  []string
	closed        bool
	closeOnce     sync.Once
	closeErr      error
}

// NewManager creates a Manager from an outbound descriptor config.
func NewManager(cfg *Config) *Manager {
	m := &Manager{handlers: make(map[string]*handler), duplicateTags: make(map[string]struct{})}
	if cfg != nil {
		for index, ob := range cfg.Outbounds {
			if ob == nil {
				m.configErrors = append(m.configErrors, fmt.Sprintf("outbound[%d] is null", index))
				continue
			}
			if strings.TrimSpace(ob.Tag) == "" {
				m.configErrors = append(m.configErrors, fmt.Sprintf("outbound[%d] has empty tag", index))
				continue
			}
			m.Add(ob)
		}
	}
	return m
}

// Add registers an outbound descriptor.
func (m *Manager) Add(ob *Outbound) {
	if ob == nil || ob.Tag == "" {
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	var replaced *handler
	if _, exists := m.handlers[ob.Tag]; !exists {
		m.order = append(m.order, ob.Tag)
	} else {
		m.duplicateTags[ob.Tag] = struct{}{}
		replaced = m.handlers[ob.Tag]
	}
	m.handlers[ob.Tag] = &handler{ob: ob}
	m.mu.Unlock()
	if replaced != nil {
		_ = replaced.Close()
	}
}

// GetHandler implements features/outbound.Manager.
func (m *Manager) GetHandler(tag string) featoutbound.Handler {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil
	}
	if h, ok := m.handlers[tag]; ok {
		if h.external != nil {
			return h.external
		}
		return h
	}
	return nil
}

// GetDefaultHandler implements features/outbound.Manager. Returns the first
// registered outbound, or nil if none.
func (m *Manager) GetDefaultHandler() featoutbound.Handler {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed || len(m.order) == 0 {
		return nil
	}
	h := m.handlers[m.order[0]]
	if h.external != nil {
		return h.external
	}
	return h
}

// Select implements features/outbound.HandlerSelector.
//
// Each selector matches by tag *prefix*: a tag is selected when `tag == s` or
// `strings.HasPrefix(tag, s)`. This is a deliberate bare-prefix match (not a
// segment-boundary match), so selector "wan" selects both "wan1" and "wan2",
// but also "wanted" — callers should use a sufficiently specific prefix to
// avoid unintended matches. Duplicates are removed and the original
// registration order is preserved.
//
// Selectors group outbounds by a common tag prefix (e.g. selector "wan" →
// "wan1", "wan2").
func (m *Manager) Select(selectors []string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(selectors) == 0 {
		// No selectors: return all tags.
		return m.allTagsLocked()
	}
	seen := make(map[string]bool, len(m.order))
	var result []string
	for _, tag := range m.order {
		if seen[tag] {
			continue
		}
		for _, sel := range selectors {
			if matchSelector(tag, sel) {
				result = append(result, tag)
				seen[tag] = true
				break
			}
		}
	}
	return result
}

// allTagsLocked returns a copy of the order slice; caller must hold mu (read).
func (m *Manager) allTagsLocked() []string {
	out := make([]string, 0, len(m.order))
	out = append(out, m.order...)
	return out
}

// matchSelector reports whether tag matches a single selector.
//
// Matches by exact equality or bare string prefix:
//   - exact equality:  "wan1" == "wan1"
//   - bare prefix:     "wan1" matches "wan"; "wanted" also matches "wan".
//
// A bare prefix is accepted because outbound grouping tags (wan1/wan2) are
// conventionally constructed as `<prefix><index>`. Callers needing tighter
// grouping should use more specific selectors.
func matchSelector(tag, selector string) bool {
	if selector == "" {
		return false
	}
	if tag == selector {
		return true
	}
	return strings.HasPrefix(tag, selector)
}

// --- features.Feature boilerplate ---

// Type implements common.HasType.
func (m *Manager) Type() interface{} { return featoutbound.ManagerType() }

// Start implements common.Runnable.
func (m *Manager) Start() error { return nil }

// Close implements common.Closable.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		handlers := make([]*handler, 0, len(m.handlers))
		for _, h := range m.handlers {
			handlers = append(handlers, h)
		}
		m.mu.Unlock()

		// Handler shutdown may perform network I/O. Do it outside the manager
		// lock so status queries remain observable while a slow handler drains.
		for _, h := range handlers {
			if err := h.Close(); err != nil && m.closeErr == nil {
				m.closeErr = err
			}
		}
	})
	return m.closeErr
}

// Validate checks the descriptor table for obvious misconfigurations.
func (m *Manager) Validate() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.handlers) == 0 {
		return errors.New("no outbound configured")
	}
	if len(m.configErrors) > 0 {
		return errors.New(strings.Join(m.configErrors, "; "))
	}
	for tag := range m.duplicateTags {
		return errors.New("duplicate outbound tag: ", tag)
	}
	for tag, h := range m.handlers {
		if tag != strings.TrimSpace(tag) {
			return errors.New("outbound tag must not contain leading or trailing whitespace: ", tag)
		}
		if h.ob.Mode == ModeProxy && (h.ob.Upstream == nil || h.ob.Upstream.Server == "") {
			return errors.New("proxy outbound ", tag, " requires upstream.server")
		}
		if h.ob.Mode == ModeProxy {
			protocol := strings.ToLower(strings.TrimSpace(h.ob.Upstream.Protocol))
			if protocol == "" {
				protocol = "socks"
			}
			host, port, err := net.SplitHostPort(h.ob.Upstream.Server)
			if err != nil {
				return errors.New("proxy outbound ", tag, " has invalid upstream.server").Base(err)
			}
			portNumber, portErr := strconv.ParseUint(port, 10, 16)
			if strings.TrimSpace(host) == "" || portErr != nil || portNumber == 0 {
				return errors.New("proxy outbound ", tag, " upstream.server must contain a host and port between 1 and 65535")
			}
			switch protocol {
			case "socks", "socks5":
				if raw, exists := h.ob.Upstream.Settings["udpMaxPacketBytes"]; exists {
					value, ok := integerSetting(raw)
					if !ok || value < 512 || value > 65245 {
						return errors.New("proxy outbound ", tag, " udpMaxPacketBytes must be an integer between 512 and 65245")
					}
				}
			case "https":
				if err := validateHTTPSProxySettings(tag, h.ob.Upstream.Settings); err != nil {
					return err
				}
			default:
				return errors.New("proxy outbound ", tag, " supports upstream.protocol=socks or https")
			}
		}
		if h.ob.Mode == ModeWireGuard {
			if err := validateWireGuard(tag, h.ob.WireGuard); err != nil {
				return err
			}
		}
		if h.ob.Bind != nil && h.ob.Bind.LocalIP != "" && net.ParseIP(h.ob.Bind.LocalIP) == nil {
			return errors.New("outbound ", tag, " has invalid bind.localIP")
		}
	}
	return nil
}

func validateHTTPSProxySettings(tag string, settings map[string]any) error {
	prefix := "https proxy outbound " + tag + " "
	allowed := map[string]struct{}{
		"username": {}, "password": {}, "tlsServerName": {}, "caFile": {},
		"insecureSkipVerify": {}, "enableHTTP2": {}, "connectTimeoutMs": {},
	}
	for key := range settings {
		if _, ok := allowed[key]; !ok {
			return errors.New(prefix, "contains unsupported setting ", key)
		}
	}
	for _, key := range []string{"username", "password", "tlsServerName", "caFile"} {
		if raw, exists := settings[key]; exists {
			if _, ok := raw.(string); !ok {
				return errors.New(prefix, key, " must be a string")
			}
		}
	}
	username, _ := settings["username"].(string)
	password, _ := settings["password"].(string)
	if strings.Contains(username, ":") {
		return errors.New(prefix, "username must not contain ':'")
	}
	if username == "" && password != "" {
		return errors.New(prefix, "username is required when password is set")
	}
	for _, key := range []string{"insecureSkipVerify", "enableHTTP2"} {
		if raw, exists := settings[key]; exists {
			if _, ok := raw.(bool); !ok {
				return errors.New(prefix, key, " must be a boolean")
			}
		}
	}
	if raw, exists := settings["connectTimeoutMs"]; exists {
		value, ok := integerSetting(raw)
		if !ok || value < 1 || value > 120000 {
			return errors.New(prefix, "connectTimeoutMs must be an integer between 1 and 120000")
		}
	}
	if raw, exists := settings["udpMaxPacketBytes"]; exists {
		return errors.New(prefix, "does not support udpMaxPacketBytes (HTTPS CONNECT is TCP-only): ", raw)
	}
	if raw, exists := settings["caFile"]; exists && strings.TrimSpace(raw.(string)) != "" {
		pem, err := os.ReadFile(raw.(string))
		if err != nil {
			return errors.New(prefix, "cannot read caFile").Base(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New(prefix, "caFile contains no certificates")
		}
	}
	return nil
}

func validateWireGuard(tag string, config *WireGuardConfig) error {
	prefix := "wireguard outbound " + tag + " "
	if config == nil {
		return errors.New(prefix, "requires wireguard settings")
	}
	private, err := wgkey.Parse(config.SecretKey)
	if err != nil {
		return errors.New(prefix, "has invalid secretKey").Base(err)
	}
	if wgkey.IsZero(private) {
		return errors.New(prefix, "secretKey must not be all zero")
	}
	if strings.TrimSpace(config.PublicKey) == "" {
		return errors.New(prefix, "requires publicKey")
	}
	configured, err := wgkey.Parse(config.PublicKey)
	if err != nil {
		return errors.New(prefix, "has invalid publicKey").Base(err)
	}
	derived, err := wgkey.Public(private)
	if err != nil || configured != derived {
		return errors.New(prefix, "publicKey does not match secretKey")
	}
	if config.MTU != 0 && (config.MTU < 576 || config.MTU > 65535) {
		return errors.New(prefix, "mtu must be between 576 and 65535")
	}
	if len(config.Reserved) != 0 && len(config.Reserved) != 3 {
		return errors.New(prefix, "reserved must be exactly 3 bytes")
	}
	for index, server := range config.DNS {
		if _, err := netip.ParseAddr(strings.TrimSpace(server)); err != nil {
			return errors.New(prefix, "has invalid dns[", index, "]").Base(err)
		}
	}
	for index, address := range config.Address {
		if _, err := netip.ParsePrefix(strings.TrimSpace(address)); err != nil {
			return errors.New(prefix, "has invalid address[", index, "]").Base(err)
		}
	}
	if len(config.Peers) == 0 {
		return errors.New(prefix, "requires at least one peer")
	}
	for index, peer := range config.Peers {
		peerPrefix := prefix + fmt.Sprintf("peer[%d] ", index)
		if peer == nil {
			return errors.New(peerPrefix, "is null")
		}
		peerPublic, err := wgkey.Parse(peer.PublicKey)
		if err != nil {
			return errors.New(peerPrefix, "has invalid publicKey").Base(err)
		}
		if wgkey.IsZero(peerPublic) {
			return errors.New(peerPrefix, "publicKey must not be all zero")
		}
		host, port, err := net.SplitHostPort(strings.TrimSpace(peer.Endpoint))
		if err != nil {
			return errors.New(peerPrefix, "has invalid endpoint").Base(err)
		}
		if strings.TrimSpace(host) == "" {
			return errors.New(peerPrefix, "endpoint host must not be empty")
		}
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil || portNumber == 0 {
			return errors.New(peerPrefix, "endpoint port must be between 1 and 65535")
		}
		if peer.PreSharedKey != "" {
			psk, err := wgkey.Parse(peer.PreSharedKey)
			if err != nil {
				return errors.New(peerPrefix, "has invalid preSharedKey").Base(err)
			}
			if wgkey.IsZero(psk) {
				return errors.New(peerPrefix, "preSharedKey must not be all zero")
			}
		}
		for allowedIndex, allowed := range peer.AllowedIPs {
			if _, err := netip.ParsePrefix(strings.TrimSpace(allowed)); err != nil {
				return errors.New(peerPrefix, "has invalid allowedIPs[", allowedIndex, "]").Base(err)
			}
		}
	}
	return nil
}

func integerSetting(raw any) (int64, bool) {
	switch value := raw.(type) {
	case int:
		return int64(value), true
	case int64:
		return value, true
	case float64:
		converted := int64(value)
		return converted, float64(converted) == value
	default:
		return 0, false
	}
}

// AddHandler registers a runtime handler (for callers building a Manager
// incrementally, e.g. from a non-JSON source).
func (m *Manager) AddHandler(_ context.Context, h featoutbound.Handler) error {
	if h == nil {
		return errors.New("nil handler")
	}
	tag := h.Tag()
	if strings.TrimSpace(tag) == "" {
		return errors.New("handler has empty tag")
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("outbound manager is closed")
	}
	old, exists := m.handlers[tag]
	if !exists {
		m.order = append(m.order, tag)
	}
	// Wrap external handlers minimally: only Tag() is reachable via GetOutbound.
	wrapped := &handler{ob: &Outbound{Tag: tag, Mode: ModeFreedom}, external: h}
	if d, ok := h.(dialer.Dialer); ok {
		wrapped.dialer = d
	}
	m.handlers[tag] = wrapped
	m.mu.Unlock()
	if old != nil {
		return old.Close()
	}
	return nil
}

// RemoveHandler removes a handler by tag.
func (m *Manager) RemoveHandler(_ context.Context, tag string) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("outbound manager is closed")
	}
	if _, ok := m.handlers[tag]; !ok {
		m.mu.Unlock()
		return errors.New("outbound ", tag, " not found")
	}
	removed := m.handlers[tag]
	delete(m.handlers, tag)
	for i, t := range m.order {
		if t == tag {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	m.mu.Unlock()
	// Removal is a lifecycle operation; close the detached handler outside the
	// manager lock so a network-backed Close cannot block unrelated readers.
	return removed.Close()
}

// GetDialer returns the Dialer for the given outbound tag, or nil.
func (m *Manager) GetDialer(tag string) dialer.Dialer {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil
	}
	h, ok := m.handlers[tag]
	m.mu.RUnlock()
	if !ok {
		return nil
	}
	return h.getDialer()
}

// GetDefaultDialer returns the dialer for the first registered outbound.
func (m *Manager) GetDefaultDialer() dialer.Dialer {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil
	}
	if len(m.order) == 0 {
		m.mu.RUnlock()
		return nil
	}
	h := m.handlers[m.order[0]]
	m.mu.RUnlock()
	return h.getDialer()
}

// dialerFactory converts an outbound descriptor to a Dialer.
var dialerFactory atomic.Value

func init() {
	dialerFactory.Store(func(*Outbound) dialer.Dialer { return nil })
}

// SetDialerFactory registers the dialer factory. Called once at CLI startup.
func SetDialerFactory(f func(ob *Outbound) dialer.Dialer) {
	if f != nil {
		dialerFactory.Store(f)
	}
}

func currentDialerFactory() func(*Outbound) dialer.Dialer {
	return dialerFactory.Load().(func(*Outbound) dialer.Dialer)
}
