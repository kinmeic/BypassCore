package conf

import (
	"encoding/json"
	"strings"

	"github.com/eugene/bypasscore/app/router"
	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/common/geodata"
	"github.com/eugene/bypasscore/common/serial"
	"google.golang.org/protobuf/proto"
)

// StrategyConfig represents a balancing strategy config.
type StrategyConfig struct {
	Type     string           `json:"type"`
	Settings *json.RawMessage `json:"settings"`
}

// BalancingRule is the JSON form of a balancer.
type BalancingRule struct {
	Tag         string         `json:"tag"`
	Selectors   StringList     `json:"selector"`
	Strategy    StrategyConfig `json:"strategy"`
	FallbackTag string         `json:"fallbackTag"`
}

// Build converts the JSON BalancingRule to a router.BalancingRule.
func (r *BalancingRule) Build() (*router.BalancingRule, error) {
	if r.Tag == "" {
		return nil, errors.New("empty balancer tag")
	}
	if len(r.Selectors) == 0 {
		return nil, errors.New("empty selector list")
	}

	r.Strategy.Type = strings.ToLower(r.Strategy.Type)
	switch r.Strategy.Type {
	case "":
		r.Strategy.Type = "random"
	case "random", "leastload", "leastping", "roundrobin":
	default:
		return nil, errors.New("unknown balancing strategy: " + r.Strategy.Type)
	}

	settings := []byte("{}")
	if r.Strategy.Settings != nil {
		settings = ([]byte)(*r.Strategy.Settings)
	}
	// Strategy settings are parsed into the least-load config when applicable.
	var ts proto.Message
	if r.Strategy.Type == "leastload" {
		var lc StrategyLeastLoadConfig
		if err := json.Unmarshal(settings, &lc); err == nil {
			ts, _ = lc.Build()
		}
	}

	return &router.BalancingRule{
		Strategy:         r.Strategy.Type,
		StrategySettings: serial.ToTypedMessage(ts),
		FallbackTag:      r.FallbackTag,
		OutboundSelector: r.Selectors,
		Tag:              r.Tag,
	}, nil
}

// StrategyLeastLoadConfig is the JSON form of the least-load strategy settings.
type StrategyLeastLoadConfig struct {
	Costs      []StrategyWeight `json:"costs"`
	Baselines  []Duration       `json:"baselines"`
	Expected   int32            `json:"expected"`
	MaxRTT     Duration         `json:"maxRTT"`
	Tolerance  float64          `json:"tolerance"`
}

// StrategyWeight is a single weighting entry.
type StrategyWeight struct {
	Regexp bool    `json:"regexp"`
	Match  string  `json:"match"`
	Value  float64 `json:"value"`
}

// Build converts to router.StrategyLeastLoadConfig.
func (c *StrategyLeastLoadConfig) Build() (*router.StrategyLeastLoadConfig, error) {
	out := &router.StrategyLeastLoadConfig{
		Expected:  c.Expected,
		MaxRTT:    int64(c.MaxRTT),
		Tolerance: float32(c.Tolerance),
	}
	for _, b := range c.Baselines {
		out.Baselines = append(out.Baselines, int64(b))
	}
	for _, w := range c.Costs {
		out.Costs = append(out.Costs, &router.StrategyWeight{
			Regexp: w.Regexp,
			Match:  w.Match,
			Value:  float32(w.Value),
		})
	}
	return out, nil
}

// Duration is a JSON duration parsed from a string (e.g. "1s").
type Duration int64

// UnmarshalJSON accepts a number (nanoseconds) or a duration string.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var ns int64
	if err := json.Unmarshal(data, &ns); err == nil {
		*d = Duration(ns)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	dur, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

// RouterConfig is the JSON form of the routing section.
type RouterConfig struct {
	RuleList       []json.RawMessage `json:"rules"`
	DomainStrategy *string           `json:"domainStrategy"`
	Balancers      []*BalancingRule  `json:"balancers"`
}

func (c *RouterConfig) getDomainStrategy() router.Config_DomainStrategy {
	ds := ""
	if c.DomainStrategy != nil {
		ds = *c.DomainStrategy
	}
	switch strings.ToLower(ds) {
	case "ipifnonmatch":
		return router.Config_IpIfNonMatch
	case "ipondemand":
		return router.Config_IpOnDemand
	default:
		return router.Config_AsIs
	}
}

// Build converts the JSON RouterConfig to a router.Config.
func (c *RouterConfig) Build() (*router.Config, error) {
	config := new(router.Config)
	config.DomainStrategy = c.getDomainStrategy()

	for _, rawRule := range c.RuleList {
		rule, err := parseRule(rawRule)
		if err != nil {
			return nil, err
		}
		config.Rule = append(config.Rule, rule)
	}
	for _, rawBalancer := range c.Balancers {
		balancer, err := rawBalancer.Build()
		if err != nil {
			return nil, err
		}
		config.BalancingRule = append(config.BalancingRule, balancer)
	}
	return config, nil
}

// RouterRule carries the outbound/balancer target.
type RouterRule struct {
	RuleTag     string `json:"ruleTag"`
	OutboundTag string `json:"outboundTag"`
	BalancerTag string `json:"balancerTag"`
}

func parseFieldRule(msg json.RawMessage) (*router.RoutingRule, error) {
	type RawFieldRule struct {
		RouterRule
		Domain     *StringList `json:"domain"`
		Domains    *StringList `json:"domains"`
		IP         *StringList `json:"ip"`
		Port       *PortList   `json:"port"`
		Network    *NetworkList `json:"network"`
		SourceIP   *StringList `json:"sourceIP"`
		Source     *StringList `json:"source"`
		SourcePort *PortList   `json:"sourcePort"`
		User       *StringList `json:"user"`
		VlessRoute *PortList   `json:"vlessRoute"`
		InboundTag *StringList `json:"inboundTag"`
		Protocols  *StringList `json:"protocol"`
		Attributes map[string]string `json:"attrs"`
		LocalIP    *StringList `json:"localIP"`
		LocalPort  *PortList   `json:"localPort"`
		Process    *StringList `json:"process"`
	}
	rawFieldRule := new(RawFieldRule)
	if err := json.Unmarshal(msg, rawFieldRule); err != nil {
		return nil, err
	}

	rule := new(router.RoutingRule)
	rule.RuleTag = rawFieldRule.RuleTag
	switch {
	case len(rawFieldRule.OutboundTag) > 0:
		rule.TargetTag = &router.RoutingRule_Tag{Tag: rawFieldRule.OutboundTag}
	case len(rawFieldRule.BalancerTag) > 0:
		rule.TargetTag = &router.RoutingRule_BalancingTag{BalancingTag: rawFieldRule.BalancerTag}
	default:
		return nil, errors.New("neither outboundTag nor balancerTag is specified in routing rule")
	}

	if rawFieldRule.Domain != nil {
		rules, err := geodata.ParseDomainRules(*rawFieldRule.Domain, geodata.Domain_Substr)
		if err != nil {
			return nil, err
		}
		rule.Domain = rules
	}
	if rawFieldRule.Domains != nil {
		rules, err := geodata.ParseDomainRules(*rawFieldRule.Domains, geodata.Domain_Substr)
		if err != nil {
			return nil, err
		}
		rule.Domain = rules
	}
	if rawFieldRule.IP != nil {
		rules, err := geodata.ParseIPRules(*rawFieldRule.IP)
		if err != nil {
			return nil, err
		}
		rule.Ip = rules
	}
	if rawFieldRule.Port != nil {
		rule.PortList = rawFieldRule.Port.Build()
	}
	if rawFieldRule.Network != nil {
		rule.Networks = rawFieldRule.Network.Build()
	}
	if rawFieldRule.SourceIP == nil {
		rawFieldRule.SourceIP = rawFieldRule.Source
	}
	if rawFieldRule.SourceIP != nil {
		rules, err := geodata.ParseIPRules(*rawFieldRule.SourceIP)
		if err != nil {
			return nil, err
		}
		rule.SourceIp = rules
	}
	if rawFieldRule.SourcePort != nil {
		rule.SourcePortList = rawFieldRule.SourcePort.Build()
	}
	if rawFieldRule.LocalIP != nil {
		rules, err := geodata.ParseIPRules(*rawFieldRule.LocalIP)
		if err != nil {
			return nil, err
		}
		rule.LocalIp = rules
	}
	if rawFieldRule.LocalPort != nil {
		rule.LocalPortList = rawFieldRule.LocalPort.Build()
	}
	if rawFieldRule.User != nil {
		rule.UserEmail = append(rule.UserEmail, *rawFieldRule.User...)
	}
	if rawFieldRule.VlessRoute != nil {
		rule.VlessRouteList = rawFieldRule.VlessRoute.Build()
	}
	if rawFieldRule.InboundTag != nil {
		rule.InboundTag = append(rule.InboundTag, *rawFieldRule.InboundTag...)
	}
	if rawFieldRule.Protocols != nil {
		rule.Protocol = append(rule.Protocol, *rawFieldRule.Protocols...)
	}
	if len(rawFieldRule.Attributes) > 0 {
		rule.Attributes = rawFieldRule.Attributes
	}
	if rawFieldRule.Process != nil && len(*rawFieldRule.Process) > 0 {
		rule.Process = *rawFieldRule.Process
	}
	return rule, nil
}

// parseRule parses a single routing rule JSON object. parseFieldRule performs
// the full parse including the outboundTag/balancerTag target validation, so
// this is a thin wrapper that supplies a clearer error context.
func parseRule(msg json.RawMessage) (*router.RoutingRule, error) {
	rule, err := parseFieldRule(msg)
	if err != nil {
		return nil, errors.New("invalid field rule").Base(err)
	}
	return rule, nil
}
