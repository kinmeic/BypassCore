// Package outbound implements the outbound descriptor model.
//
// Each outbound is a lightweight *descriptor*: a tagged entry carrying its
// binding metadata (interface / local IP / upstream proxy). The routing engine
// only ever emits a tag; the upper layer (proxy client, gateway, TUN, …) looks
// the tag up in this table and interprets the binding.
//
// This is what makes wan1/wan2 first-class: they are simply freedom-mode
// outbounds bound to a network interface / source IP.
package outbound

import (
	"strings"
	"sync"

	"github.com/eugene/bypasscore/app/dialer"
	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/features/outbound"
)

// Mode describes how traffic matched to an outbound should be carried.
type Mode int

const (
	// ModeFreedom carries traffic directly from the local machine. May bind to a
	// specific interface / source IP via Bind (this is how wan1/wan2 work).
	ModeFreedom Mode = iota
	// ModeBlackhole drops the traffic.
	ModeBlackhole
	// ModeProxy forwards traffic to an upstream proxy server described by Upstream.
	ModeProxy
)

// String returns the JSON-friendly name of the mode.
func (m Mode) String() string {
	switch m {
	case ModeFreedom:
		return "freedom"
	case ModeBlackhole:
		return "blackhole"
	case ModeProxy:
		return "proxy"
	default:
		return "unknown"
	}
}

// UnmarshalJSON parses Mode from a JSON string ("freedom"/"blackhole"/"proxy").
// Unknown values are rejected so a typo cannot silently become direct access.
func (m *Mode) UnmarshalJSON(data []byte) error {
	s := strings.Trim(strings.Trim(string(data), `"`), " ")
	switch strings.ToLower(s) {
	case "", "freedom", "direct":
		*m = ModeFreedom
	case "blackhole", "block":
		*m = ModeBlackhole
	case "proxy":
		*m = ModeProxy
	default:
		return errors.New("unknown outbound mode: ", s)
	}
	return nil
}

// MarshalJSON renders Mode back to its string form.
func (m Mode) MarshalJSON() ([]byte, error) {
	return []byte(`"` + m.String() + `"`), nil
}

// BindConfig is the L3 binding for a freedom outbound. Either field may be empty.
type BindConfig struct {
	// Interface is a network interface name, e.g. "en0", "wan1".
	Interface string `json:"interface,omitempty"`
	// LocalIP is the source IP to dial from.
	LocalIP string `json:"localIP,omitempty"`
}

// UpstreamConfig describes an upstream proxy for a proxy-mode outbound.
// Settings is an open map so the engine stays protocol-agnostic; the upper
// layer interprets protocol-specific fields.
type UpstreamConfig struct {
	// Protocol is the proxy protocol, e.g. "trojan", "vless", "socks", "shadowsocks".
	Protocol string `json:"protocol"`
	// Server is the upstream server "host:port".
	Server string `json:"server"`
	// Settings holds protocol-specific options (password, uuid, encryption, …).
	Settings map[string]any `json:"settings,omitempty"`
}

// Outbound is a single outbound descriptor.
type Outbound struct {
	// Tag is the unique outbound identifier referenced by routing rules/balancers.
	Tag string `json:"tag"`
	// Mode determines how matched traffic is carried.
	// Accepted JSON values: "freedom", "blackhole", "proxy".
	Mode Mode `json:"mode"`
	// Bind is the optional L3 binding (only meaningful for ModeFreedom).
	Bind *BindConfig `json:"bind,omitempty"`
	// Upstream is the optional upstream proxy (required for ModeProxy).
	Upstream *UpstreamConfig `json:"upstream,omitempty"`
}

// Config is the outbound section of the BypassCore config.
type Config struct {
	Outbounds []*Outbound `json:"outbounds"`
}

// handler wraps an Outbound so it satisfies the features/outbound.Handler
// interface (which only needs Tag() plus the Feature lifecycle methods).
type handler struct {
	ob       *Outbound
	external outbound.Handler
	dialer   dialer.Dialer
	// dialerOnce confines lazy construction to this outbound. A slow factory
	// no longer serializes unrelated outbound lookups behind Manager.mu.
	dialerOnce sync.Once
}

func (h *handler) getDialer() dialer.Dialer {
	h.dialerOnce.Do(func() {
		if h.dialer == nil {
			h.dialer = currentDialerFactory()(h.ob)
		}
	})
	return h.dialer
}

func (h *handler) Tag() string { return h.ob.Tag }
func (h *handler) Type() interface{} {
	if h.external != nil {
		return h.external.Type()
	}
	return outbound.ManagerType()
}
func (h *handler) Start() error {
	if h.external != nil {
		return h.external.Start()
	}
	return nil
}
func (h *handler) Close() error {
	if h.external != nil {
		return h.external.Close()
	}
	return nil
}

// GetOutbound returns the raw descriptor for a tag, or nil.
func (m *Manager) GetOutbound(tag string) *Outbound {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if h, ok := m.handlers[tag]; ok {
		return h.ob
	}
	return nil
}

// List returns all registered outbound descriptors in registration order.
func (m *Manager) List() []*Outbound {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Outbound, 0, len(m.order))
	for _, tag := range m.order {
		if h, ok := m.handlers[tag]; ok {
			out = append(out, h.ob)
		}
	}
	return out
}
