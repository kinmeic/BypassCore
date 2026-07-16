package router

import (
	"context"
	"strings"
	"sync"

	"github.com/eugene/bypasscore/common"
	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/common/serial"
	"github.com/eugene/bypasscore/core"
	"github.com/eugene/bypasscore/features/dns"
	"github.com/eugene/bypasscore/features/extension"
	"github.com/eugene/bypasscore/features/outbound"
	"github.com/eugene/bypasscore/features/routing"
	routing_dns "github.com/eugene/bypasscore/features/routing/dns"
)

// Router is an implementation of routing.Router.
type Router struct {
	domainStrategy   Config_DomainStrategy
	rules            []*Rule
	balancers        map[string]*Balancer
	finalOutboundTag string
	dns              dns.Client

	ctx        context.Context
	ohm        outbound.Manager
	dispatcher routing.Dispatcher
	mu         sync.RWMutex
	reloadMu   sync.Mutex
}

// Route is an implementation of routing.Route.
type Route struct {
	routing.Context
	outboundGroupTags []string
	outboundTag       string
	ruleTag           string
}

// Init initializes the Router.
func (r *Router) Init(ctx context.Context, config *Config, d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
	if config == nil {
		return errors.New("nil router config")
	}
	if ohm == nil && len(config.BalancingRule) > 0 {
		return errors.New("router with balancers requires outbound manager")
	}
	var observer extension.Observatory
	_ = core.RequireFeatures(ctx, func(value extension.Observatory) error {
		observer = value
		return nil
	})
	for _, rule := range config.BalancingRule {
		if rule == nil {
			return errors.New("nil balancing rule")
		}
		strategy := strings.ToLower(rule.Strategy)
		if (strategy == "leastping" || strategy == "leastload") && observer == nil {
			return errors.New("balancer ", rule.Tag, " requires observatory")
		}
	}
	r.domainStrategy = config.DomainStrategy
	r.finalOutboundTag = config.FinalOutboundTag
	r.dns = d
	r.ctx = ctx
	r.ohm = ohm
	r.dispatcher = dispatcher

	r.balancers = make(map[string]*Balancer, len(config.BalancingRule))
	for _, rule := range config.BalancingRule {
		if rule.Tag == "" {
			return errors.New("empty balancer tag")
		}
		if _, exists := r.balancers[rule.Tag]; exists {
			return errors.New("duplicate balancer tag ", rule.Tag)
		}
		balancer, err := rule.Build(ohm, dispatcher)
		if err != nil {
			return err
		}
		balancer.InjectContext(ctx)
		r.balancers[rule.Tag] = balancer
	}

	r.rules = make([]*Rule, 0, len(config.Rule))
	ruleTags := make(map[string]struct{}, len(config.Rule))
	for _, rule := range config.Rule {
		if rule == nil {
			r.closeWebhooks()
			return errors.New("nil routing rule")
		}
		if tag := rule.GetRuleTag(); tag != "" {
			if _, exists := ruleTags[tag]; exists {
				r.closeWebhooks()
				return errors.New("duplicate ruleTag ", tag)
			}
			ruleTags[tag] = struct{}{}
		}
		cond, err := rule.BuildCondition()
		if err != nil {
			r.closeWebhooks()
			return err
		}
		rr := &Rule{
			Condition: cond,
			Tag:       rule.GetTag(),
			RuleTag:   rule.GetRuleTag(),
		}
		if wh := rule.GetWebhook(); wh != nil {
			notifier, err := NewWebhookNotifier(wh)
			if err != nil {
				r.closeWebhooks()
				return err
			}
			rr.Webhook = notifier
		}
		btag := rule.GetBalancingTag()
		if len(btag) > 0 {
			brule, found := r.balancers[btag]
			if !found {
				if rr.Webhook != nil {
					rr.Webhook.Close()
				}
				r.closeWebhooks()
				return errors.New("balancer ", btag, " not found")
			}
			rr.Balancer = brule
		}
		r.rules = append(r.rules, rr)
	}

	return nil
}

// PickRoute implements routing.Router.
//
// It is safe to call concurrently with other PickRoute calls and with
// ReloadRules/RemoveRule: the rules slice is snapshotted under a read lock and
// then evaluated without the lock held, so rule application (which may perform
// blocking DNS resolution) never blocks rule mutations.
func (r *Router) PickRoute(ctx routing.Context) (routing.Route, error) {
	originalCtx := ctx
	rule, ctx, err := r.pickRouteInternal(ctx)
	if err != nil {
		if err == common.ErrNoClue {
			r.mu.RLock()
			finalTag := r.finalOutboundTag
			r.mu.RUnlock()
			if finalTag != "" {
				return &Route{Context: ctx, outboundTag: finalTag}, nil
			}
		}
		return nil, err
	}
	tag, err := rule.GetTag()
	if err != nil {
		return nil, err
	}
	if rule.Webhook != nil {
		rule.Webhook.Fire(originalCtx, tag)
	}
	return &Route{Context: ctx, outboundTag: tag, ruleTag: rule.RuleTag}, nil
}

// AddRule implements routing.Router.
func (r *Router) AddRule(config *serial.TypedMessage, shouldAppend bool) error {
	inst, err := config.GetInstance()
	if err != nil {
		return err
	}
	if c, ok := inst.(*Config); ok {
		return r.ReloadRules(c, shouldAppend)
	}
	return errors.New("AddRule: config type error")
}

func (r *Router) ReloadRules(config *Config, shouldAppend bool) error {
	if config == nil {
		return errors.New("nil router config")
	}
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	r.mu.RLock()
	ctx, ohm, dispatcher := r.ctx, r.ohm, r.dispatcher
	baseRules := append([]*Rule(nil), r.rules...)
	baseBalancers := make(map[string]*Balancer, len(r.balancers))
	for tag, balancer := range r.balancers {
		baseBalancers[tag] = balancer
	}
	r.mu.RUnlock()
	if !shouldAppend {
		baseRules = nil
		baseBalancers = make(map[string]*Balancer, len(config.BalancingRule))
	}

	newBalancers := baseBalancers
	var observer extension.Observatory
	_ = core.RequireFeatures(ctx, func(value extension.Observatory) error {
		observer = value
		return nil
	})
	for _, rule := range config.BalancingRule {
		if rule == nil || rule.Tag == "" {
			return errors.New("nil or empty balancing rule")
		}
		if _, found := newBalancers[rule.Tag]; found {
			return errors.New("duplicate balancer tag ", rule.Tag)
		}
		strategy := strings.ToLower(rule.Strategy)
		if (strategy == "leastping" || strategy == "leastload") && observer == nil {
			return errors.New("balancer ", rule.Tag, " requires observatory")
		}
		balancer, err := rule.Build(ohm, dispatcher)
		if err != nil {
			return err
		}
		balancer.InjectContext(ctx)
		newBalancers[rule.Tag] = balancer
	}

	newRules := append([]*Rule(nil), baseRules...)
	ruleTags := make(map[string]struct{}, len(baseRules)+len(config.Rule))
	for _, rule := range baseRules {
		if rule.RuleTag != "" {
			ruleTags[rule.RuleTag] = struct{}{}
		}
	}
	var createdWebhooks []*WebhookNotifier
	fail := func(err error) error {
		for _, webhook := range createdWebhooks {
			webhook.Close()
		}
		return err
	}
	for _, rule := range config.Rule {
		if rule == nil {
			return fail(errors.New("nil routing rule"))
		}
		if tag := rule.GetRuleTag(); tag != "" {
			if _, exists := ruleTags[tag]; exists {
				return fail(errors.New("duplicate ruleTag ", tag))
			}
			ruleTags[tag] = struct{}{}
		}
		cond, err := rule.BuildCondition()
		if err != nil {
			return fail(err)
		}
		rr := &Rule{Condition: cond, Tag: rule.GetTag(), RuleTag: rule.GetRuleTag()}
		if wh := rule.GetWebhook(); wh != nil {
			notifier, err := NewWebhookNotifier(wh)
			if err != nil {
				return fail(err)
			}
			rr.Webhook = notifier
			createdWebhooks = append(createdWebhooks, notifier)
		}
		if tag := rule.GetBalancingTag(); tag != "" {
			balancer, found := newBalancers[tag]
			if !found {
				return fail(errors.New("balancer ", tag, " not found"))
			}
			rr.Balancer = balancer
		}
		newRules = append(newRules, rr)
	}

	r.mu.Lock()
	oldRules := r.rules
	r.rules = newRules
	r.balancers = newBalancers
	if !shouldAppend {
		r.domainStrategy = config.DomainStrategy
		r.finalOutboundTag = config.FinalOutboundTag
	}
	r.mu.Unlock()
	if !shouldAppend {
		for _, rule := range oldRules {
			if rule.Webhook != nil {
				rule.Webhook.Close()
			}
		}
	}
	return nil
}

// RuleExists reports whether a rule with the given ruleTag is registered.
func (r *Router) RuleExists(tag string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ruleExistsLocked(tag)
}

func (r *Router) ruleExistsLocked(tag string) bool {
	if tag != "" {
		for _, rule := range r.rules {
			if rule.RuleTag == tag {
				return true
			}
		}
	}
	return false
}

// RemoveRule implements routing.Router.
func (r *Router) RemoveRule(tag string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	newRules := []*Rule{}
	if tag != "" {
		for _, rule := range r.rules {
			if rule.RuleTag != tag {
				newRules = append(newRules, rule)
			} else if rule.Webhook != nil {
				rule.Webhook.Close()
			}
		}
		r.rules = newRules
		return nil
	}
	return errors.New("empty tag name!")
}

// ListRule implements routing.Router
func (r *Router) ListRule() []routing.Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ruleList := make([]routing.Route, 0)
	for _, rule := range r.rules {
		ruleList = append(ruleList, &Route{
			outboundTag: rule.Tag,
			ruleTag:     rule.RuleTag,
		})
	}
	return ruleList
}

func (r *Router) pickRouteInternal(ctx routing.Context) (*Rule, routing.Context, error) {
	// Snapshot the rule set and strategy under the read lock so concurrent
	// ReloadRules/RemoveRule mutations cannot race with iteration. The snapshot
	// (rule pointers are shared, but the slice header is stable) is then
	// evaluated without the lock, allowing rule.Apply to block on DNS without
	// holding off rule mutations.
	r.mu.RLock()
	rules := append([]*Rule(nil), r.rules...)
	strategy := r.domainStrategy
	dnsClient := r.dns
	r.mu.RUnlock()

	// SkipDNSResolve is set from DNS module.
	// the DOH remote server maybe a domain name,
	// this prevents cycle resolving dead loop
	skipDNSResolve := ctx.GetSkipDNSResolve()

	if strategy == Config_IpOnDemand && !skipDNSResolve {
		ctx = routing_dns.ContextWithDNSClient(ctx, dnsClient)
	}

	for _, rule := range rules {
		if rule.Apply(ctx) {
			return rule, ctx, nil
		}
	}

	if strategy != Config_IpIfNonMatch || len(ctx.GetTargetDomain()) == 0 || skipDNSResolve {
		return nil, ctx, common.ErrNoClue
	}

	ctx = routing_dns.ContextWithDNSClient(ctx, dnsClient)

	// Try applying rules again if we have IPs.
	for _, rule := range rules {
		if rule.Apply(ctx) {
			return rule, ctx, nil
		}
	}

	return nil, ctx, common.ErrNoClue
}

// Start implements common.Runnable.
func (r *Router) Start() error {
	return nil
}

// closeWebhooks closes all webhook notifiers in the current rule set.
func (r *Router) closeWebhooks() {
	for _, rule := range r.rules {
		if rule.Webhook != nil {
			rule.Webhook.Close()
		}
	}
}

// Close implements common.Closable.
func (r *Router) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeWebhooks()
	return nil
}

// Type implements common.HasType.
func (*Router) Type() interface{} {
	return routing.RouterType()
}

// GetOutboundGroupTags implements routing.Route.
func (r *Route) GetOutboundGroupTags() []string {
	return r.outboundGroupTags
}

// GetOutboundTag implements routing.Route.
func (r *Route) GetOutboundTag() string {
	return r.outboundTag
}

func (r *Route) GetRuleTag() string {
	return r.ruleTag
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		r := new(Router)
		if err := core.RequireFeatures(ctx, func(d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
			return r.Init(ctx, config.(*Config), d, ohm, dispatcher)
		}); err != nil {
			return nil, err
		}
		return r, nil
	}))
}
