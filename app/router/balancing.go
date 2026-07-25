package router

import (
	"context"
	sync "sync"

	"github.com/eugene/bypasscore/app/observatory"
	"github.com/eugene/bypasscore/common"
	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/core"
	"github.com/eugene/bypasscore/features/extension"
	"github.com/eugene/bypasscore/features/outbound"
)

type BalancingStrategy interface {
	PickOutbound([]string) string
}

type BalancingPrincipleTarget interface {
	GetPrincipleTarget([]string) []string
}

type RoundRobinStrategy struct {
	FallbackTag string

	ctx         context.Context
	observatory extension.Observatory
	alive       aliveCache
	mu          sync.Mutex
	index       int
}

func (s *RoundRobinStrategy) InjectContext(ctx context.Context) {
	s.ctx = ctx
	if len(s.FallbackTag) > 0 {
		common.Must(core.RequireFeatures(s.ctx, func(observatory extension.Observatory) error {
			s.observatory = observatory
			return nil
		}))
	}
}

func (s *RoundRobinStrategy) GetPrincipleTarget(strings []string) []string {
	return strings
}

func (s *RoundRobinStrategy) PickOutbound(tags []string) string {
	if s.observatory != nil {
		observeReport, err := s.observatory.GetObservation(s.ctx)
		if err == nil {
			if result, ok := observeReport.(*observatory.ObservationResult); ok {
				tags = s.alive.filter(tags, result.Status)
			}
		}
	}

	n := len(tags)
	if n == 0 {
		// goes to fallbackTag
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tag := tags[s.index%n]
	s.index = (s.index + 1) % n
	return tag
}

func filterAliveCandidates(candidates []string, statuses []*observatory.OutboundStatus) []string {
	var alive []string
	for index, candidate := range candidates {
		isAlive := true // an unobserved candidate is considered alive
		for _, status := range statuses {
			if status.OutboundTag == candidate {
				isAlive = status.Alive
				break
			}
		}
		if !isAlive && alive == nil {
			alive = make([]string, index, len(candidates)-1)
			copy(alive, candidates[:index])
		} else if isAlive && alive != nil {
			alive = append(alive, candidate)
		}
	}
	if alive == nil {
		return candidates
	}
	return alive
}

// statusFingerprint returns an order-independent fingerprint of observation
// statuses. GetObservation builds its result by ranging over a map, so status
// order varies between calls and a positional hash would report a change on
// every call.
func statusFingerprint(statuses []*observatory.OutboundStatus) uint64 {
	var fp uint64
	for _, status := range statuses {
		h := uint64(14695981039346656037) // FNV-1a offset basis
		for i := 0; i < len(status.OutboundTag); i++ {
			h ^= uint64(status.OutboundTag[i])
			h *= 1099511628211 // FNV prime
		}
		if status.Alive {
			h ^= 0x9e3779b97f4a7c15
		}
		fp += h
	}
	return fp
}

// aliveCache memoizes the alive-filtered candidate list. Observation results
// only change when a probe round completes, so re-filtering on every
// connection wastes work and allocations whenever any outbound is down.
type aliveCache struct {
	mu          sync.Mutex
	fingerprint uint64
	candidates  []string
	alive       []string
}

func (c *aliveCache) filter(candidates []string, statuses []*observatory.OutboundStatus) []string {
	fp := statusFingerprint(statuses)
	c.mu.Lock()
	defer c.mu.Unlock()
	if fp == c.fingerprint && stringSlicesEqual(c.candidates, candidates) {
		return c.alive
	}
	alive := filterAliveCandidates(candidates, statuses)
	c.fingerprint = fp
	c.candidates = append(c.candidates[:0], candidates...)
	c.alive = alive
	return alive
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type Balancer struct {
	selectors   []string
	strategy    BalancingStrategy
	ohm         outbound.Manager
	fallbackTag string

	override override
}

// PickOutbound picks the tag of a outbound
func (b *Balancer) PickOutbound() (string, error) {
	candidates, err := b.SelectOutbounds()
	if err != nil {
		if b.fallbackTag != "" {
			errors.LogInfo(context.Background(), "fallback to [", b.fallbackTag, "], due to error: ", err)
			return b.fallbackTag, nil
		}
		return "", err
	}
	var tag string
	if o := b.override.Get(); o != "" {
		tag = o
	} else {
		tag = b.strategy.PickOutbound(candidates)
	}
	if tag == "" {
		if b.fallbackTag != "" {
			errors.LogInfo(context.Background(), "fallback to [", b.fallbackTag, "], due to empty tag returned")
			return b.fallbackTag, nil
		}
		// will use default handler
		return "", errors.New("balancing strategy returns empty tag")
	}
	return tag, nil
}

func (b *Balancer) InjectContext(ctx context.Context) {
	if contextReceiver, ok := b.strategy.(extension.ContextReceiver); ok {
		contextReceiver.InjectContext(ctx)
	}
}

// SelectOutbounds select outbounds with selectors of the Balancer
func (b *Balancer) SelectOutbounds() ([]string, error) {
	hs, ok := b.ohm.(outbound.HandlerSelector)
	if !ok {
		return nil, errors.New("outbound.Manager is not a HandlerSelector")
	}
	tags := hs.Select(b.selectors)
	return tags, nil
}

// GetPrincipleTarget implements routing.BalancerPrincipleTarget
func (r *Router) GetPrincipleTarget(tag string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if b, ok := r.balancers[tag]; ok {
		if s, ok := b.strategy.(BalancingPrincipleTarget); ok {
			candidates, err := b.SelectOutbounds()
			if err != nil {
				return nil, errors.New("unable to select outbounds").Base(err)
			}
			return s.GetPrincipleTarget(candidates), nil
		}
		return nil, errors.New("unsupported GetPrincipleTarget")
	}
	return nil, errors.New("cannot find tag")
}

// SetOverrideTarget implements routing.BalancerOverrider
func (r *Router) SetOverrideTarget(tag, target string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if b, ok := r.balancers[tag]; ok {
		b.override.Put(target)
		return nil
	}
	return errors.New("cannot find tag")
}

// GetOverrideTarget implements routing.BalancerOverrider
func (r *Router) GetOverrideTarget(tag string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if b, ok := r.balancers[tag]; ok {
		return b.override.Get(), nil
	}
	return "", errors.New("cannot find tag")
}
