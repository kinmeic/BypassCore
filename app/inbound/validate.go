package inbound

import (
	"net"
	"strings"

	"github.com/eugene/bypasscore/common/errors"
)

// ValidateConfig checks an inbound without opening sockets. It is shared by
// --check-config and SIGHUP reload validation so an invalid replacement never
// disturbs running listeners.
func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return errors.New("nil inbound configuration")
	}
	if strings.TrimSpace(cfg.Tag) == "" {
		return errors.New("inbound tag must not be empty")
	}
	if cfg.Tag != strings.TrimSpace(cfg.Tag) {
		return errors.New("inbound tag must not contain leading or trailing whitespace")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return errors.New("inbound port must be between 1 and 65535")
	}
	if host := strings.Trim(strings.TrimSpace(cfg.Listen), "[]"); host != "" && net.ParseIP(host) == nil {
		return errors.New("inbound listen must be an IP address")
	}
	typ := strings.ToLower(strings.TrimSpace(cfg.Type))
	if typ == "" {
		typ = "redirect"
	}
	wantTCP, wantUDP, err := parseInboundNetworks(cfg.Network)
	if err != nil {
		return err
	}
	if !wantTCP && !wantUDP {
		return errors.New("inbound network must enable TCP and/or UDP")
	}
	switch typ {
	case "dns", "dot", "doh":
		if _, err := positiveLimit(cfg.MaxConcurrentQueries, defaultDNSMaxConcurrentQueries, "maxConcurrentQueries"); err != nil {
			return err
		}
		if typ == "doh" && cfg.MaxConcurrentQueries > maxDoHConcurrentStreams {
			return errors.New("DNS inbound: DoH maxConcurrentQueries must not exceed ", maxDoHConcurrentStreams)
		}
		if _, err := positiveLimit(cfg.MaxTCPConnections, defaultDNSMaxTCPConnections, "maxTCPConnections"); err != nil {
			return err
		}
		if _, err := queryByteLimit(cfg.MaxQueryBytes); err != nil {
			return err
		}
		if _, _, _, err := newDNSAccessPolicy(cfg); err != nil {
			return err
		}
		if _, err := compileDNSRules(cfg.DNSRules); err != nil {
			return err
		}
		if _, err := newDNSRawCacheWithLimit(cfg.DNSRawCacheEntries, cfg.DNSRawCacheMaxTTLSeconds, cfg.DNSRawCacheMaxBytes); err != nil {
			return err
		}
		if typ != "dns" && (!wantTCP || wantUDP) {
			return errors.New("DNS inbound: dot/doh require network=tcp")
		}
		if typ == "dot" || typ == "doh" {
			if _, err := loadDNSServerTLSConfig(cfg); err != nil {
				return err
			}
		}
		if typ == "doh" && cfg.DNSDoHPath != "" && !strings.HasPrefix(cfg.DNSDoHPath, "/") {
			return errors.New("DNS inbound: dnsDoHPath must start with /")
		}
	case "redirect", "tproxy":
		if wantUDP && typ != "tproxy" {
			return errors.New("inbound: UDP requires type=tproxy")
		}
		if wantUDP {
			if _, err := udpResourceLimitsFromConfig(cfg); err != nil {
				return err
			}
		}
	default:
		return errors.New("inbound type must be redirect, tproxy, dns, dot, or doh")
	}
	return nil
}
