package outbound

import (
	"context"
	"strings"

	"github.com/eugene/bypasscore/common/errors"
	featoutbound "github.com/eugene/bypasscore/features/outbound"
)

// Manager is a config-driven outbound.Manager. It is backed by the Outbound
// descriptor table and also implements HandlerSelector so the router's balancer
// can resolve selector prefixes to concrete tags.
type Manager struct {
	// handlers maps tag -> wrapped descriptor.
	handlers map[string]*handler
	// order preserves insertion order so the first registered outbound is the
	// default.
	order []string
}

// NewManager creates a Manager from an outbound descriptor config.
func NewManager(cfg *Config) *Manager {
	m := &Manager{handlers: make(map[string]*handler)}
	if cfg != nil {
		for _, ob := range cfg.Outbounds {
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
	if _, exists := m.handlers[ob.Tag]; !exists {
		m.order = append(m.order, ob.Tag)
	}
	m.handlers[ob.Tag] = &handler{ob: ob}
}

// GetHandler implements features/outbound.Manager.
func (m *Manager) GetHandler(tag string) featoutbound.Handler {
	if h, ok := m.handlers[tag]; ok {
		return h
	}
	return nil
}

// GetDefaultHandler implements features/outbound.Manager. Returns the first
// registered outbound, or nil if none.
func (m *Manager) GetDefaultHandler() featoutbound.Handler {
	if len(m.order) == 0 {
		return nil
	}
	return m.handlers[m.order[0]]
}

// Select implements features/outbound.HandlerSelector.
//
// Each selector matches by tag *prefix*: a tag is selected if it equals or has
// a dotted/underscored segment boundary after any selector. To keep things
// simple and predictable for wan1/wan2-style grouping, a tag matches selector
// `s` when `tag == s` or `strings.HasPrefix(tag, s)`. Duplicates are removed and
// the original registration order is preserved.
//
// Selectors group outbounds by a common tag prefix (e.g. selector "wan" →
// "wan1", "wan2").
func (m *Manager) Select(selectors []string) []string {
	if len(selectors) == 0 {
		// No selectors: return all tags.
		return m.allTags()
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

func (m *Manager) allTags() []string {
	out := make([]string, 0, len(m.order))
	out = append(out, m.order...)
	return out
}

// matchSelector reports whether tag matches a single selector.
//
// Matches:
//   - exact equality:  "wan1" == "wan1"
//   - prefix boundary: "wan1" matches "wan" (the remainder "1" is a continuation),
//                       but "wan1-extra" also matches "wan1".
//
// A bare prefix is accepted because outbound grouping tags (wan1/wan2) are
// conventionally constructed as `<prefix><index>`.
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
func (m *Manager) Close() error { return nil }

// Validate checks the descriptor table for obvious misconfigurations.
func (m *Manager) Validate() error {
	if len(m.handlers) == 0 {
		return errors.New("no outbound configured")
	}
	for tag, h := range m.handlers {
		if h.ob.Mode == ModeProxy && (h.ob.Upstream == nil || h.ob.Upstream.Server == "") {
			return errors.New("proxy outbound ", tag, " requires upstream.server")
		}
	}
	return nil
}

// AddHandler registers a runtime handler (for callers building a Manager
// incrementally, e.g. from a non-JSON source).
func (m *Manager) AddHandler(_ context.Context, h featoutbound.Handler) error {
	if h == nil {
		return errors.New("nil handler")
	}
	tag := h.Tag()
	if _, exists := m.handlers[tag]; !exists {
		m.order = append(m.order, tag)
	}
	// Wrap external handlers minimally: only Tag() is reachable via GetOutbound.
	m.handlers[tag] = &handler{ob: &Outbound{Tag: tag, Mode: ModeFreedom}}
	return nil
}

// RemoveHandler removes a handler by tag.
func (m *Manager) RemoveHandler(_ context.Context, tag string) error {
	if _, ok := m.handlers[tag]; !ok {
		return errors.New("outbound ", tag, " not found")
	}
	delete(m.handlers, tag)
	for i, t := range m.order {
		if t == tag {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	return nil
}
