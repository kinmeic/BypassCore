package inbound

import (
	"strconv"
	"strings"

	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/common/geodata"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsRuleAction uint8

const (
	dnsActionDirect dnsRuleAction = iota
	dnsActionDrop
	dnsActionReturn
	dnsActionHijack
)

type compiledDNSRule struct {
	matcher geodata.DomainMatcher
	qtypes  map[dnsmessage.Type]struct{}
	action  dnsRuleAction
	rcode   dnsmessage.RCode
}

func compileDNSRules(configs []DNSRuleConfig) ([]compiledDNSRule, error) {
	rules := make([]compiledDNSRule, 0, len(configs))
	for index, config := range configs {
		rule := compiledDNSRule{qtypes: make(map[dnsmessage.Type]struct{}), rcode: dnsmessage.RCode(config.RCode)}
		switch strings.ToLower(strings.TrimSpace(config.Action)) {
		case "direct", "forward", "proxy":
			// The selected DNS server's tag still travels through Router/Outbound;
			// "proxy" is therefore an explicit alias for raw forwarding.
			rule.action = dnsActionDirect
		case "drop":
			rule.action = dnsActionDrop
		case "return", "reject":
			rule.action = dnsActionReturn
		case "hijack":
			rule.action = dnsActionHijack
		default:
			return nil, errors.New("DNS inbound: dnsRules[", index, "] has invalid action")
		}
		if config.RCode > 0x0fff {
			return nil, errors.New("DNS inbound: dnsRules[", index, "] rcode must be <= 4095")
		}
		for _, rawType := range config.QType {
			qtype, err := parseDNSQType(rawType)
			if err != nil {
				return nil, errors.New("DNS inbound: dnsRules[", index, "] invalid qType").Base(err)
			}
			rule.qtypes[qtype] = struct{}{}
		}
		if len(config.Domain) > 0 {
			domains, err := geodata.ParseDomainRules(config.Domain, geodata.Domain_Substr)
			if err != nil {
				return nil, errors.New("DNS inbound: dnsRules[", index, "] invalid domain").Base(err)
			}
			matcher, err := geodata.DomainReg.BuildDomainMatcher(domains)
			if err != nil {
				return nil, errors.New("DNS inbound: dnsRules[", index, "] matcher build failed").Base(err)
			}
			rule.matcher = matcher
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseDNSQType(value string) (dnsmessage.Type, error) {
	names := map[string]dnsmessage.Type{
		"A": dnsmessage.TypeA, "NS": dnsmessage.TypeNS, "CNAME": dnsmessage.TypeCNAME,
		"SOA": dnsmessage.TypeSOA, "PTR": dnsmessage.TypePTR, "MX": dnsmessage.TypeMX,
		"TXT": dnsmessage.TypeTXT, "AAAA": dnsmessage.TypeAAAA, "SRV": dnsmessage.TypeSRV,
		"OPT": dnsmessage.TypeOPT, "SVCB": dnsmessage.Type(64), "HTTPS": dnsmessage.Type(65),
		"CAA": dnsmessage.Type(257),
	}
	value = strings.ToUpper(strings.TrimSpace(value))
	if qtype, ok := names[value]; ok {
		return qtype, nil
	}
	n, err := strconv.ParseUint(value, 10, 16)
	if err != nil || n == 0 {
		return 0, errors.New("unknown DNS qType ", value)
	}
	return dnsmessage.Type(n), nil
}

func (l *DNSListener) dnsAction(question dnsmessage.Question) (dnsRuleAction, dnsmessage.RCode) {
	domain := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))
	for _, rule := range l.currentPolicy().dnsRules {
		if len(rule.qtypes) > 0 {
			if _, ok := rule.qtypes[question.Type]; !ok {
				continue
			}
		}
		if rule.matcher != nil && !rule.matcher.MatchAny(domain) {
			continue
		}
		return rule.action, rule.rcode
	}
	if question.Type == dnsmessage.TypeA || question.Type == dnsmessage.TypeAAAA {
		return dnsActionHijack, dnsmessage.RCodeSuccess
	}
	return dnsActionDirect, dnsmessage.RCodeSuccess
}
