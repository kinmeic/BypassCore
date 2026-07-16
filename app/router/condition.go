package router

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/common/geodata"
	"github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/features/routing"
	"github.com/eugene/bypasscore/features/routing/dns"
)

type Condition interface {
	Apply(ctx routing.Context) bool
}

type ConditionChan []Condition

func NewConditionChan() *ConditionChan {
	var condChan ConditionChan = make([]Condition, 0, 8)
	return &condChan
}

func (v *ConditionChan) Add(cond Condition) *ConditionChan {
	*v = append(*v, cond)
	return v
}

// Apply applies all conditions registered in this chan.
func (v *ConditionChan) Apply(ctx routing.Context) bool {
	for _, cond := range *v {
		if !cond.Apply(ctx) {
			return false
		}
	}
	return true
}

func (v *ConditionChan) Len() int {
	return len(*v)
}

type DomainMatcher struct{ geodata.DomainMatcher }

func NewDomainMatcher(rules []*geodata.DomainRule) (*DomainMatcher, error) {
	m, err := geodata.DomainReg.BuildDomainMatcher(rules)
	if err != nil {
		return nil, err
	}
	return &DomainMatcher{DomainMatcher: m}, nil
}

func (m *DomainMatcher) ApplyDomain(domain string) bool {
	return m.DomainMatcher.MatchAny(strings.ToLower(domain))
}

// Apply implements Condition.
func (m *DomainMatcher) Apply(ctx routing.Context) bool {
	domain := ctx.GetTargetDomain()
	if len(domain) == 0 {
		return false
	}
	return m.DomainMatcher.MatchAny(strings.ToLower(domain))
}

type MatcherAsType byte

const (
	MatcherAsType_Local MatcherAsType = iota
	MatcherAsType_Source
	MatcherAsType_Target
	MatcherAsType_VlessRoute // for port
)

type IPMatcher struct {
	matcher geodata.IPMatcher
	asType  MatcherAsType
}

func NewIPMatcher(rules []*geodata.IPRule, asType MatcherAsType) (*IPMatcher, error) {
	m, err := geodata.IPReg.BuildIPMatcher(rules)
	if err != nil {
		return nil, err
	}
	return &IPMatcher{matcher: m, asType: asType}, nil
}

// Apply implements Condition.
func (m *IPMatcher) Apply(ctx routing.Context) bool {
	var ips []net.IP

	switch m.asType {
	case MatcherAsType_Local:
		ips = ctx.GetLocalIPs()
	case MatcherAsType_Source:
		ips = ctx.GetSourceIPs()
	case MatcherAsType_Target:
		ips = ctx.GetTargetIPs()
	default:
		panic("unk asType")
	}

	return m.matcher.AnyMatch(ips)
}

type PortMatcher struct {
	port   net.MemoryPortList
	asType MatcherAsType
}

// NewPortMatcher create a new port matcher that can match source or local or destination port
func NewPortMatcher(list *net.PortList, asType MatcherAsType) *PortMatcher {
	return &PortMatcher{
		port:   net.PortListFromProto(list),
		asType: asType,
	}
}

// Apply implements Condition.
func (v *PortMatcher) Apply(ctx routing.Context) bool {
	switch v.asType {
	case MatcherAsType_Local:
		return v.port.Contains(ctx.GetLocalPort())
	case MatcherAsType_Source:
		return v.port.Contains(ctx.GetSourcePort())
	case MatcherAsType_Target:
		return v.port.Contains(ctx.GetTargetPort())
	case MatcherAsType_VlessRoute:
		return v.port.Contains(ctx.GetVlessRoute())
	default:
		panic("unk asType")
	}
}

type NetworkMatcher struct {
	list [8]bool
}

func NewNetworkMatcher(network []net.Network) NetworkMatcher {
	var matcher NetworkMatcher
	for _, n := range network {
		matcher.list[int(n)] = true
	}
	return matcher
}

// Apply implements Condition.
func (v NetworkMatcher) Apply(ctx routing.Context) bool {
	return v.list[int(ctx.GetNetwork())]
}

type UserMatcher struct {
	user    []string
	pattern []*regexp.Regexp
}

func NewUserMatcher(users []string) *UserMatcher {
	valid := make([]string, 0, len(users))
	for _, user := range users {
		if pattern, ok := strings.CutPrefix(user, "regexp:"); ok {
			if pattern == "" {
				continue
			}
			if _, err := regexp.Compile(pattern); err != nil {
				continue
			}
		}
		valid = append(valid, user)
	}
	matcher, _ := NewUserMatcherChecked(valid)
	return matcher
}

// NewUserMatcherChecked compiles user patterns and reports invalid regular
// expressions instead of silently weakening a routing rule.
func NewUserMatcherChecked(users []string) (*UserMatcher, error) {
	usersCopy := make([]string, 0, len(users))
	patternsCopy := make([]*regexp.Regexp, 0, len(users))
	for _, user := range users {
		if user == "" {
			continue
		}
		// "regexp:<pattern>" entries compile <pattern> and match by regex.
		// A bare "regexp:" (empty pattern) is dropped as meaningless.
		if pattern, ok := strings.CutPrefix(user, "regexp:"); ok {
			if pattern == "" {
				return nil, errors.New("empty user regexp")
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, errors.New("invalid user regexp").Base(err)
			}
			patternsCopy = append(patternsCopy, re)
			continue
		}
		usersCopy = append(usersCopy, user)
	}
	return &UserMatcher{
		user:    usersCopy,
		pattern: patternsCopy,
	}, nil
}

// Apply implements Condition.
func (v *UserMatcher) Apply(ctx routing.Context) bool {
	user := ctx.GetUser()
	if len(user) == 0 {
		return false
	}
	for _, u := range v.user {
		if u == user {
			return true
		}
	}
	for _, re := range v.pattern {
		if re.MatchString(user) {
			return true
		}
	}
	return false
}

type InboundTagMatcher struct {
	tags []string
}

func NewInboundTagMatcher(tags []string) *InboundTagMatcher {
	tagsCopy := make([]string, 0, len(tags))
	for _, tag := range tags {
		if len(tag) > 0 {
			tagsCopy = append(tagsCopy, tag)
		}
	}
	return &InboundTagMatcher{
		tags: tagsCopy,
	}
}

// Apply implements Condition.
func (v *InboundTagMatcher) Apply(ctx routing.Context) bool {
	tag := ctx.GetInboundTag()
	if len(tag) == 0 {
		return false
	}
	for _, t := range v.tags {
		if t == tag {
			return true
		}
	}
	return false
}

type ProtocolMatcher struct {
	protocols []string
}

func NewProtocolMatcher(protocols []string) *ProtocolMatcher {
	pCopy := make([]string, 0, len(protocols))

	for _, p := range protocols {
		if len(p) > 0 {
			pCopy = append(pCopy, p)
		}
	}

	return &ProtocolMatcher{
		protocols: pCopy,
	}
}

// Apply implements Condition.
func (m *ProtocolMatcher) Apply(ctx routing.Context) bool {
	protocol := ctx.GetProtocol()
	if len(protocol) == 0 {
		return false
	}
	for _, p := range m.protocols {
		if strings.HasPrefix(protocol, p) {
			return true
		}
	}
	return false
}

type AttributeMatcher struct {
	configuredKeys map[string]*regexp.Regexp
}

// Match implements attributes matching.
func (m *AttributeMatcher) Match(attrs map[string]string) bool {
	// header keys are case insensitive most likely. So we do a convert
	httpHeaders := make(map[string]string)
	for key, value := range attrs {
		httpHeaders[strings.ToLower(key)] = value
	}
	for key, regex := range m.configuredKeys {
		if a, ok := httpHeaders[key]; !ok || !regex.MatchString(a) {
			return false
		}
	}
	return true
}

// Apply implements Condition.
func (m *AttributeMatcher) Apply(ctx routing.Context) bool {
	attributes := ctx.GetAttributes()
	if attributes == nil {
		return false
	}
	return m.Match(attributes)
}

type ProcessNameMatcher struct {
	ProcessNames []string
	AbsPaths     []string
	Folders      []string
	MatchSelf    bool
}

func NewProcessNameMatcher(names []string) *ProcessNameMatcher {
	processNames := []string{}
	folders := []string{}
	absPaths := []string{}
	matchSelf := false
	for _, name := range names {
		if name == "self/" {
			matchSelf = true
			continue
		}
		name := filepath.ToSlash(name)
		// /usr/bin/
		if strings.HasSuffix(name, "/") {
			folders = append(folders, name)
			continue
		}
		// /usr/bin/curl
		if strings.Contains(name, "/") {
			absPaths = append(absPaths, name)
			continue
		}
		// curl.exe or curl
		processNames = append(processNames, strings.TrimSuffix(name, ".exe"))
	}
	return &ProcessNameMatcher{
		ProcessNames: processNames,
		AbsPaths:     absPaths,
		Folders:      folders,
		MatchSelf:    matchSelf,
	}
}

func (m *ProcessNameMatcher) Apply(ctx routing.Context) bool {
	if len(ctx.GetSourceIPs()) == 0 {
		return false
	}

	srcPort := uint16(ctx.GetSourcePort())
	srcIP := ctx.GetSourceIPs()[0].String()

	var network string
	switch ctx.GetNetwork() {
	case net.Network_TCP:
		network = "tcp"
	case net.Network_UDP:
		network = "udp"
	default:
		return false
	}

	var dstIP string
	var dstPort uint16 = 0

	// do not use resolved IP because Android process lookup needs original dst ip
	resolvableContext, ok := ctx.(*dns.ResolvableContext)
	if ok && len(resolvableContext.Context.GetTargetIPs()) > 0 {
		dstIP = resolvableContext.Context.GetTargetIPs()[0].String()
		dstPort = uint16(resolvableContext.Context.GetTargetPort())
	} else if len(ctx.GetTargetIPs()) > 0 {
		dstIP = ctx.GetTargetIPs()[0].String()
		dstPort = uint16(ctx.GetTargetPort())
	}

	pid, name, absPath, err := cachedFindProcess(network, srcIP, uint16(srcPort), dstIP, uint16(dstPort))
	if err != nil {
		if err != net.ErrNotLocal {
			errors.LogError(context.Background(), "Unables to find local process name: ", err)
		}
		return false
	}
	if m.MatchSelf {
		if pid == os.Getpid() {
			return true
		}
	}
	if slices.Contains(m.ProcessNames, name) {
		return true
	}
	if slices.Contains(m.AbsPaths, absPath) {
		return true
	}
	for _, f := range m.Folders {
		if strings.HasPrefix(absPath, f) {
			return true
		}
	}
	return false
}
