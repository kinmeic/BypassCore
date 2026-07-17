// Package dnsnftset writes selected DNS A/AAAA results into nftables sets.
package dnsnftset

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	defaultQueueSize       = 256
	defaultBatchSize       = 128
	defaultFlushIntervalMs = 25
)

var nftIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

// Config controls the bounded asynchronous DNS-result writer.
type Config struct {
	QueueSize       int      `json:"queueSize,omitempty"`
	BatchSize       int      `json:"batchSize,omitempty"`
	FlushIntervalMs int      `json:"flushIntervalMs,omitempty"`
	Policies        []Policy `json:"policies"`
}

// Policy maps one or more DNS server tags to IPv4/IPv6 nftables sets. Set
// names use the same family@table@set notation as ChinaDNS-NG.
type Policy struct {
	ServerTags []string `json:"serverTags"`
	IPv4Set    string   `json:"ipv4Set,omitempty"`
	IPv6Set    string   `json:"ipv6Set,omitempty"`
}

type setRef struct {
	family    string
	table     string
	name      string
	ipVersion int
}

func (r setRef) String() string { return r.family + "@" + r.table + "@" + r.name }

// NormalizeConfig applies defaults and validates a configuration without
// touching netlink or requiring the target sets to exist yet.
func NormalizeConfig(config *Config) (Config, error) {
	if config == nil {
		return Config{}, errors.New("DNS result NFTSets: nil config")
	}
	c := *config
	if c.QueueSize == 0 {
		c.QueueSize = defaultQueueSize
	}
	if c.QueueSize < 1 || c.QueueSize > 4096 {
		return Config{}, errors.New("DNS result NFTSets: queueSize must be between 1 and 4096")
	}
	if c.BatchSize == 0 {
		c.BatchSize = defaultBatchSize
	}
	if c.BatchSize < 1 || c.BatchSize > 1024 {
		return Config{}, errors.New("DNS result NFTSets: batchSize must be between 1 and 1024")
	}
	if c.FlushIntervalMs == 0 {
		c.FlushIntervalMs = defaultFlushIntervalMs
	}
	if c.FlushIntervalMs < 1 || c.FlushIntervalMs > 1000 {
		return Config{}, errors.New("DNS result NFTSets: flushIntervalMs must be between 1 and 1000")
	}
	if len(c.Policies) == 0 {
		return Config{}, errors.New("DNS result NFTSets: at least one policy is required")
	}

	c.Policies = append([]Policy(nil), c.Policies...)
	for i := range c.Policies {
		policy := &c.Policies[i]
		if len(policy.ServerTags) == 0 {
			return Config{}, fmt.Errorf("DNS result NFTSets: policies[%d] requires serverTags", i)
		}
		seen := make(map[string]struct{}, len(policy.ServerTags))
		policy.ServerTags = append([]string(nil), policy.ServerTags...)
		for j, raw := range policy.ServerTags {
			tag := strings.TrimSpace(raw)
			if tag == "" {
				return Config{}, fmt.Errorf("DNS result NFTSets: policies[%d].serverTags[%d] is empty", i, j)
			}
			if _, exists := seen[tag]; exists {
				return Config{}, fmt.Errorf("DNS result NFTSets: policies[%d] repeats server tag %q", i, tag)
			}
			seen[tag] = struct{}{}
			policy.ServerTags[j] = tag
		}
		policy.IPv4Set = strings.TrimSpace(policy.IPv4Set)
		policy.IPv6Set = strings.TrimSpace(policy.IPv6Set)
		if policy.IPv4Set == "" && policy.IPv6Set == "" {
			return Config{}, fmt.Errorf("DNS result NFTSets: policies[%d] requires ipv4Set and/or ipv6Set", i)
		}
		if policy.IPv4Set != "" {
			if _, err := parseSetRef(policy.IPv4Set, 4); err != nil {
				return Config{}, fmt.Errorf("DNS result NFTSets: policies[%d].ipv4Set: %w", i, err)
			}
		}
		if policy.IPv6Set != "" {
			if _, err := parseSetRef(policy.IPv6Set, 6); err != nil {
				return Config{}, fmt.Errorf("DNS result NFTSets: policies[%d].ipv6Set: %w", i, err)
			}
		}
	}
	return c, nil
}

// Validate checks a configuration without allocating runtime resources.
func Validate(config *Config) error { _, err := NormalizeConfig(config); return err }

func parseSetRef(raw string, ipVersion int) (setRef, error) {
	parts := strings.Split(raw, "@")
	if len(parts) != 3 {
		return setRef{}, errors.New("set must use family@table@set notation")
	}
	ref := setRef{
		family:    strings.ToLower(strings.TrimSpace(parts[0])),
		table:     strings.TrimSpace(parts[1]),
		name:      strings.TrimSpace(parts[2]),
		ipVersion: ipVersion,
	}
	if ref.family != "inet" && ref.family != "ip" && ref.family != "ip6" {
		return setRef{}, fmt.Errorf("unsupported table family %q", ref.family)
	}
	if ipVersion == 4 && ref.family == "ip6" {
		return setRef{}, errors.New("IPv4 results cannot target an ip6-family table")
	}
	if ipVersion == 6 && ref.family == "ip" {
		return setRef{}, errors.New("IPv6 results cannot target an ip-family table")
	}
	if ref.table == "" || len(ref.table) > 255 || !nftIdentifier.MatchString(ref.table) {
		return setRef{}, fmt.Errorf("invalid table name %q", ref.table)
	}
	if ref.name == "" || len(ref.name) > 255 || !nftIdentifier.MatchString(ref.name) {
		return setRef{}, fmt.Errorf("invalid set name %q", ref.name)
	}
	return ref, nil
}
