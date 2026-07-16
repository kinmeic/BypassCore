package inbound

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSRulesMatchInOrder(t *testing.T) {
	rules, err := compileDNSRules([]DNSRuleConfig{
		{Domain: []string{"domain:blocked.example"}, QType: []string{"TXT"}, Action: "return", RCode: uint16(dnsmessage.RCodeRefused)},
		{Domain: []string{"domain:blocked.example"}, Action: "drop"},
		{QType: []string{"A"}, Action: "direct"},
	})
	if err != nil {
		t.Fatal(err)
	}
	l := &DNSListener{dnsRules: rules}
	name := dnsmessage.MustNewName("www.blocked.example.")
	if action, rcode := l.dnsAction(dnsmessage.Question{Name: name, Type: dnsmessage.TypeTXT}); action != dnsActionReturn || rcode != dnsmessage.RCodeRefused {
		t.Fatalf("TXT action=%v rcode=%v", action, rcode)
	}
	if action, _ := l.dnsAction(dnsmessage.Question{Name: name, Type: dnsmessage.TypeMX}); action != dnsActionDrop {
		t.Fatalf("MX action=%v, want drop", action)
	}
	other := dnsmessage.MustNewName("other.example.")
	if action, _ := l.dnsAction(dnsmessage.Question{Name: other, Type: dnsmessage.TypeA}); action != dnsActionDirect {
		t.Fatalf("A action=%v, want direct rule", action)
	}
	if action, _ := l.dnsAction(dnsmessage.Question{Name: other, Type: dnsmessage.TypeAAAA}); action != dnsActionHijack {
		t.Fatalf("AAAA default action=%v, want hijack", action)
	}
}

func TestDNSRulesRejectInvalidConfiguration(t *testing.T) {
	tests := [][]DNSRuleConfig{
		{{Action: "unknown"}},
		{{Action: "return", RCode: 4096}},
		{{Action: "drop", QType: []string{"not-a-type"}}},
		{{Action: "drop", Domain: []string{"regexp:["}}},
	}
	for _, rules := range tests {
		if _, err := compileDNSRules(rules); err == nil {
			t.Fatalf("invalid DNS rules accepted: %+v", rules)
		}
	}
}

func TestDNSRuleActionsAffectListener(t *testing.T) {
	rules, err := compileDNSRules([]DNSRuleConfig{{QType: []string{"A"}, Action: "return", RCode: uint16(dnsmessage.RCodeRefused)}})
	if err != nil {
		t.Fatal(err)
	}
	l := NewDNS(&Config{}, &stubDNSClient{})
	l.dnsRules = rules
	response, err := l.handleQuery(dnsQuery(t, 11, dnsmessage.TypeA), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := unpackDNS(t, response).RCode; got != dnsmessage.RCodeRefused {
		t.Fatalf("rcode=%v, want REFUSED", got)
	}
}
