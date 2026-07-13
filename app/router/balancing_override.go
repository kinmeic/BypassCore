package router

import (
	sync "sync"

	"github.com/eugene/bypasscore/common/errors"
)

// OverrideBalancer pins a balancer to always return the given target tag,
// bypassing its strategy. Equivalent to SetOverrideTarget but kept for API
// compatibility with callers that expect the explicit override verb.
func (r *Router) OverrideBalancer(balancer string, target string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, found := r.balancers[balancer]
	if !found {
		return errors.New("balancer '", balancer, "' not found")
	}
	b.override.Put(target)
	return nil
}

type overrideSettings struct {
	target string
}

type override struct {
	access   sync.RWMutex
	settings overrideSettings
}

// Get gets the override settings
func (o *override) Get() string {
	o.access.RLock()
	defer o.access.RUnlock()
	return o.settings.target
}

// Put updates the override settings
func (o *override) Put(target string) {
	o.access.Lock()
	defer o.access.Unlock()
	o.settings.target = target
}

// Clear clears the override settings
func (o *override) Clear() {
	o.access.Lock()
	defer o.access.Unlock()
	o.settings.target = ""
}
