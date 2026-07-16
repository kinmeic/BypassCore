package conf

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/eugene/bypasscore/app/dns"
	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/common/geodata"
	"github.com/eugene/bypasscore/common/net"
)

// NameServerConfig is the JSON form of a DNS upstream server. Accepts either a
// bare address string or a full object.
type NameServerConfig struct {
	Address         *Address   `json:"address"`
	ClientIP        *Address   `json:"clientIp"`
	Port            uint16     `json:"port"`
	SkipFallback    bool       `json:"skipFallback"`
	Domains         StringList `json:"domains"`
	ExpectedIPs     StringList `json:"expectedIPs"`
	ExpectIPs       StringList `json:"expectIPs"`
	QueryStrategy   string     `json:"queryStrategy"`
	Tag             string     `json:"tag"`
	TimeoutMs       uint64     `json:"timeoutMs"`
	DisableCache    *bool      `json:"disableCache"`
	ServeStale      *bool      `json:"serveStale"`
	ServeExpiredTTL *uint32    `json:"serveExpiredTTL"`
	FinalQuery      bool       `json:"finalQuery"`
	UnexpectedIPs   StringList `json:"unexpectedIPs"`
	OutboundTag     string     `json:"outboundTag,omitempty"`
}

// UnmarshalJSON accepts a bare address string or a full object.
func (c *NameServerConfig) UnmarshalJSON(data []byte) error {
	var address Address
	if err := json.Unmarshal(data, &address); err == nil {
		c.Address = &address
		return nil
	}

	var advanced struct {
		Address         *Address   `json:"address"`
		ClientIP        *Address   `json:"clientIp"`
		Port            uint16     `json:"port"`
		SkipFallback    bool       `json:"skipFallback"`
		Domains         StringList `json:"domains"`
		ExpectedIPs     StringList `json:"expectedIPs"`
		ExpectIPs       StringList `json:"expectIPs"`
		QueryStrategy   string     `json:"queryStrategy"`
		Tag             string     `json:"tag"`
		TimeoutMs       uint64     `json:"timeoutMs"`
		DisableCache    *bool      `json:"disableCache"`
		ServeStale      *bool      `json:"serveStale"`
		ServeExpiredTTL *uint32    `json:"serveExpiredTTL"`
		FinalQuery      bool       `json:"finalQuery"`
		UnexpectedIPs   StringList `json:"unexpectedIPs"`
		OutboundTag     string     `json:"outboundTag,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&advanced); err == nil {
		c.Address = advanced.Address
		c.ClientIP = advanced.ClientIP
		c.Port = advanced.Port
		c.SkipFallback = advanced.SkipFallback
		c.Domains = advanced.Domains
		c.ExpectedIPs = advanced.ExpectedIPs
		c.ExpectIPs = advanced.ExpectIPs
		c.QueryStrategy = advanced.QueryStrategy
		c.Tag = advanced.Tag
		c.TimeoutMs = advanced.TimeoutMs
		c.DisableCache = advanced.DisableCache
		c.ServeStale = advanced.ServeStale
		c.ServeExpiredTTL = advanced.ServeExpiredTTL
		c.FinalQuery = advanced.FinalQuery
		c.UnexpectedIPs = advanced.UnexpectedIPs
		c.OutboundTag = advanced.OutboundTag
		return nil
	}
	return errors.New("failed to parse name server: ", string(data))
}

// Build converts the JSON NameServerConfig to a proto dns.NameServer.
func (c *NameServerConfig) Build() (*dns.NameServer, error) {
	if c.Address == nil {
		return nil, errors.New("nameserver address is not specified")
	}
	queryStrategy, err := resolveQueryStrategy(c.QueryStrategy)
	if err != nil {
		return nil, err
	}

	domainRules, err := geodata.ParseDomainRules(c.Domains, geodata.Domain_Substr)
	if err != nil {
		return nil, err
	}

	if len(c.ExpectedIPs) == 0 {
		c.ExpectedIPs = c.ExpectIPs
	}

	actPrior := false
	var newExpectedIPs StringList
	for _, s := range c.ExpectedIPs {
		if s == "*" {
			actPrior = true
		} else {
			newExpectedIPs = append(newExpectedIPs, s)
		}
	}

	actUnprior := false
	var newUnexpectedIPs StringList
	for _, s := range c.UnexpectedIPs {
		if s == "*" {
			actUnprior = true
		} else {
			newUnexpectedIPs = append(newUnexpectedIPs, s)
		}
	}

	expectedIPRules, err := geodata.ParseIPRules(newExpectedIPs)
	if err != nil {
		return nil, err
	}
	unexpectedIPRules, err := geodata.ParseIPRules(newUnexpectedIPs)
	if err != nil {
		return nil, err
	}

	var myClientIP []byte
	if c.ClientIP != nil {
		if !c.ClientIP.Family().IsIP() {
			return nil, errors.New("not an IP address: ", c.ClientIP.String())
		}
		myClientIP = []byte(c.ClientIP.IP())
	}

	return &dns.NameServer{
		Address: &net.Endpoint{
			Network: net.Network_UDP,
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
		},
		ClientIp:        myClientIP,
		SkipFallback:    c.SkipFallback,
		Domain:          domainRules,
		ExpectedIp:      expectedIPRules,
		QueryStrategy:   queryStrategy,
		ActPrior:        actPrior,
		Tag:             strings.TrimSpace(c.Tag),
		TimeoutMs:       c.TimeoutMs,
		DisableCache:    c.DisableCache,
		ServeStale:      c.ServeStale,
		ServeExpiredTTL: c.ServeExpiredTTL,
		FinalQuery:      c.FinalQuery,
		UnexpectedIp:    unexpectedIPRules,
		ActUnprior:      actUnprior,
		OutboundTag:     strings.TrimSpace(c.OutboundTag),
	}, nil
}

// Build converts the Address to a net.IPOrDomain (mirrors Xray's Address.Build).
func (v *Address) Build() *net.IPOrDomain {
	if v == nil {
		return &net.IPOrDomain{}
	}
	return net.NewIPOrDomain(v.Address)
}

// HostAddress holds a single host mapping value (one IP, multiple IPs, or a proxied domain).
type HostAddress struct {
	addr  *Address
	addrs []*Address
}

// UnmarshalJSON accepts a single address or an array of addresses.
func (h *HostAddress) UnmarshalJSON(data []byte) error {
	addr := new(Address)
	var addrs []*Address
	switch {
	case json.Unmarshal(data, &addr) == nil:
		h.addr = addr
	case json.Unmarshal(data, &addrs) == nil:
		h.addrs = addrs
	default:
		return errors.New("invalid address")
	}
	return nil
}

// MarshalJSON renders the host address.
func (h *HostAddress) MarshalJSON() ([]byte, error) {
	if h.addr != nil {
		return json.Marshal(h.addr)
	} else if h.addrs != nil {
		return json.Marshal(h.addrs)
	}
	return nil, errors.New("unexpected config state")
}

// HostsWrapper wraps the hosts map.
type HostsWrapper struct {
	Hosts map[string]*HostAddress
}

// UnmarshalJSON parses the hosts object.
func (m *HostsWrapper) UnmarshalJSON(data []byte) error {
	hosts := make(map[string]*HostAddress)
	if err := json.Unmarshal(data, &hosts); err == nil {
		m.Hosts = hosts
		return nil
	}
	return errors.New("invalid DNS hosts").Base(errors.New(string(data)))
}

// MarshalJSON renders the hosts object.
func (m *HostsWrapper) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.Hosts)
}

func newHostMapping(ha *HostAddress) *dns.Config_HostMapping {
	if ha.addr != nil {
		if ha.addr.Family().IsDomain() {
			return &dns.Config_HostMapping{ProxiedDomain: ha.addr.Address.Domain()}
		}
		return &dns.Config_HostMapping{Ip: [][]byte{ha.addr.Address.IP()}}
	}
	ips := make([][]byte, 0, len(ha.addrs))
	for _, addr := range ha.addrs {
		if addr.Family().IsDomain() {
			return &dns.Config_HostMapping{ProxiedDomain: addr.Address.Domain()}
		}
		ips = append(ips, []byte(addr.Address.IP()))
	}
	return &dns.Config_HostMapping{Ip: ips}
}

// Build converts HostsWrapper to a list of HostMapping.
func (m *HostsWrapper) Build() ([]*dns.Config_HostMapping, error) {
	mappings := make([]*dns.Config_HostMapping, 0, len(m.Hosts))
	for rule, addrs := range m.Hosts {
		mapping := newHostMapping(addrs)
		dr, err := geodata.ParseDomainRule(rule, geodata.Domain_Full)
		if err != nil {
			return nil, err
		}
		mapping.Domain = dr
		mappings = append(mappings, mapping)
	}
	return mappings, nil
}

// DNSConfig is the JSON form of the top-level DNS configuration.
type DNSConfig struct {
	Servers                []*NameServerConfig `json:"servers"`
	Hosts                  *HostsWrapper       `json:"hosts"`
	ClientIP               *Address            `json:"clientIp"`
	Tag                    string              `json:"tag"`
	QueryStrategy          string              `json:"queryStrategy"`
	DisableCache           bool                `json:"disableCache"`
	ServeStale             bool                `json:"serveStale"`
	ServeExpiredTTL        uint32              `json:"serveExpiredTTL"`
	DisableFallback        bool                `json:"disableFallback"`
	DisableFallbackIfMatch bool                `json:"disableFallbackIfMatch"`
	EnableParallelQuery    bool                `json:"enableParallelQuery"`
	UseSystemHosts         bool                `json:"useSystemHosts"`
}

// Build converts the JSON DNSConfig to a proto dns.Config.
func (c *DNSConfig) Build() (*dns.Config, error) {
	queryStrategy, err := resolveQueryStrategy(c.QueryStrategy)
	if err != nil {
		return nil, err
	}
	config := &dns.Config{
		Tag:                    c.Tag,
		DisableCache:           c.DisableCache,
		ServeStale:             c.ServeStale,
		ServeExpiredTTL:        c.ServeExpiredTTL,
		DisableFallback:        c.DisableFallback,
		DisableFallbackIfMatch: c.DisableFallbackIfMatch,
		EnableParallelQuery:    c.EnableParallelQuery,
		QueryStrategy:          queryStrategy,
	}

	if c.ClientIP != nil {
		if !c.ClientIP.Family().IsIP() {
			return nil, errors.New("not an IP address: ", c.ClientIP.String())
		}
		config.ClientIp = []byte(c.ClientIP.IP())
	}

	// Build PolicyID: servers with identical policy attributes share an ID so
	// they can be raced in parallel-query mode.
	policyMap := map[string]uint32{}
	nextPolicyID := uint32(1)
	buildPolicyID := func(nsc *NameServerConfig) uint32 {
		var sb strings.Builder
		if nsc.ClientIP != nil {
			sb.WriteString("client=")
			sb.WriteString(nsc.ClientIP.String())
			sb.WriteByte('|')
		} else {
			sb.WriteString("client=none|")
		}
		if nsc.SkipFallback {
			sb.WriteString("skip=1|")
		} else {
			sb.WriteString("skip=0|")
		}
		sb.WriteString("qs=")
		sb.WriteString(strings.ToLower(strings.TrimSpace(nsc.QueryStrategy)))
		sb.WriteByte('|')
		sb.WriteString("tag=")
		sb.WriteString(strings.ToLower(strings.TrimSpace(nsc.Tag)))
		sb.WriteByte('|')

		writeList := func(tag string, lst []string) {
			if len(lst) == 0 {
				sb.WriteString(tag)
				sb.WriteString("=[]|")
				return
			}
			cp := make([]string, len(lst))
			for i, s := range lst {
				cp[i] = strings.TrimSpace(strings.ToLower(s))
			}
			sort.Strings(cp)
			sb.WriteString(tag)
			sb.WriteByte('=')
			sb.WriteString(strings.Join(cp, ","))
			sb.WriteByte('|')
		}
		writeList("domains", nsc.Domains)
		writeList("expected", nsc.ExpectedIPs)
		writeList("expect", nsc.ExpectIPs)
		writeList("unexpected", nsc.UnexpectedIPs)

		key := sb.String()
		if id, ok := policyMap[key]; ok {
			return id
		}
		id := nextPolicyID
		nextPolicyID++
		policyMap[key] = id
		return id
	}

	for _, server := range c.Servers {
		ns, err := server.Build()
		if err != nil {
			return nil, errors.New("failed to build nameserver").Base(err)
		}
		ns.PolicyID = buildPolicyID(server)
		config.NameServer = append(config.NameServer, ns)
	}

	if c.Hosts != nil {
		staticHosts, err := c.Hosts.Build()
		if err != nil {
			return nil, errors.New("failed to build hosts").Base(err)
		}
		config.StaticHosts = append(config.StaticHosts, staticHosts...)
	}
	if c.UseSystemHosts {
		systemHosts, err := readSystemHosts()
		if err != nil {
			return nil, errors.New("failed to read system hosts").Base(err)
		}
		config.StaticHosts = append(config.StaticHosts, systemHosts...)
	}

	return config, nil
}

func resolveQueryStrategy(queryStrategy string) (dns.QueryStrategy, error) {
	switch strings.ToLower(strings.TrimSpace(queryStrategy)) {
	case "", "useip", "use_ip", "use-ip":
		return dns.QueryStrategy_USE_IP, nil
	case "useip4", "useipv4", "use_ip4", "use_ipv4", "use_ip_v4", "use-ip4", "use-ipv4", "use-ip-v4":
		return dns.QueryStrategy_USE_IP4, nil
	case "useip6", "useipv6", "use_ip6", "use_ipv6", "use_ip_v6", "use-ip6", "use-ipv6", "use-ip-v6":
		return dns.QueryStrategy_USE_IP6, nil
	case "usesys", "usesystem", "use_sys", "use_system", "use-sys", "use-system":
		return dns.QueryStrategy_USE_SYS, nil
	default:
		return dns.QueryStrategy_USE_IP, errors.New("unknown DNS query strategy: " + queryStrategy)
	}
}

func readSystemHosts() ([]*dns.Config_HostMapping, error) {
	var hostsPath string
	switch runtime.GOOS {
	case "windows":
		hostsPath = filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
	default:
		hostsPath = "/etc/hosts"
	}
	file, err := os.Open(hostsPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readSystemHostsFrom(file)
}

func readSystemHostsFrom(r io.Reader) ([]*dns.Config_HostMapping, error) {
	hosts := make(map[string][][]byte, 16)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[0:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		addr := net.ParseAddress(f[0])
		if addr.Family().IsDomain() {
			continue
		}
		for i := 1; i < len(f); i++ {
			domain := strings.TrimSuffix(f[i], ".")
			domain = strings.ToLower(domain)
			hosts[domain] = append(hosts[domain], addr.IP())
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	hostsMap := make([]*dns.Config_HostMapping, 0, len(hosts))
	for domain, ips := range hosts {
		rule, err := geodata.ParseDomainRule(domain, geodata.Domain_Full)
		if err != nil {
			return nil, err
		}
		hostsMap = append(hostsMap, &dns.Config_HostMapping{
			Domain: rule,
			Ip:     ips,
		})
	}
	return hostsMap, nil
}
