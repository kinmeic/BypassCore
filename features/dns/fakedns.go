package dns

import (
	"github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/features"
)

// FakeDNSEngine allocates fake IPs from a reserved pool and maps them back to
// domains. BypassCore does not implement a FakeIP engine; these interfaces are
// retained so callers that reference them compile.
type FakeDNSEngine interface {
	features.Feature
	GetFakeIPForDomain(domain string) []net.Address
	GetDomainFromFakeDNS(ip net.Address) string
}

// FakeDNSEngineRev0 extends FakeDNSEngine with pool-membership checks.
type FakeDNSEngineRev0 interface {
	FakeDNSEngine
	IsIPInIPPool(ip net.Address) bool
	GetFakeIPForDomain3(domain string, IPv4, IPv6 bool) []net.Address
}

// FakeIPv4Pool is the default IPv4 fake-address pool.
var FakeIPv4Pool = "198.18.0.0/15"

// FakeIPv6Pool is the default IPv6 fake-address pool.
var FakeIPv6Pool = "fc00::/18"
