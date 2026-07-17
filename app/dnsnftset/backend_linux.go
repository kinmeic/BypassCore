//go:build linux

package dnsnftset

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

type netlinkBackend struct {
	mu   sync.RWMutex
	sets map[string]*nftables.Set
}

func newBackend() backend { return &netlinkBackend{sets: make(map[string]*nftables.Set)} }

func (b *netlinkBackend) Probe(refs []setRef) error {
	sets := make(map[string]*nftables.Set, len(refs))
	var failures []error
	for _, ref := range refs {
		set, err := resolveSet(ref)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		sets[setCacheKey(ref)] = set
	}
	b.mu.Lock()
	b.sets = sets
	b.mu.Unlock()
	return errors.Join(failures...)
}

func (b *netlinkBackend) Add(updates []update) []writeResult {
	results := make([]writeResult, len(updates))
	groups := make(map[string][]int)
	var order []string
	for i, item := range updates {
		key := setCacheKey(item.set)
		if _, exists := groups[key]; !exists {
			order = append(order, key)
		}
		groups[key] = append(groups[key], i)
	}
	for _, key := range order {
		indices := groups[key]
		ref := updates[indices[0]].set
		set, err := b.resolve(ref)
		if err == nil {
			elementCapacity := len(indices)
			if set.Interval {
				elementCapacity *= 2
			}
			elements := make([]nftables.SetElement, 0, elementCapacity)
			for _, index := range indices {
				elements = append(elements, nftElements(set, updates[index])...)
			}
			conn := &nftables.Conn{}
			err = conn.SetAddElements(set, elements)
			if err == nil {
				err = conn.Flush()
			}
		}
		if err == nil {
			for _, index := range indices {
				results[index].applied = true
			}
			continue
		}
		// An overlapping static interval makes this set's transaction fail
		// atomically. Retry individually so that CIDR/GeoIP membership is reported
		// as existing without suppressing unrelated DNS results. Exact elements
		// take the successful path above: the kernel refreshes dynamic timeouts and
		// leaves permanent elements permanent. Refresh cached metadata first
		// because a supervisor may have recreated the table.
		b.invalidate(key, set)
		set, resolveErr := b.resolve(ref)
		if resolveErr != nil {
			for _, index := range indices {
				results[index].err = resolveErr
			}
			continue
		}
		for _, index := range indices {
			oneErr := addOne(set, updates[index])
			switch {
			case oneErr == nil:
				results[index].applied = true
			case isAlreadyExists(oneErr):
				results[index].existing = true
			default:
				results[index].err = oneErr
			}
		}
	}
	return results
}

func addOne(set *nftables.Set, item update) error {
	conn := &nftables.Conn{}
	if err := conn.SetAddElements(set, nftElements(set, item)); err != nil {
		return fmt.Errorf("DNS result NFTSets: prepare %s element %s: %w", item.set.String(), net.IP(item.key), err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("DNS result NFTSets: add %s element %s: %w", item.set.String(), net.IP(item.key), err)
	}
	return nil
}

func nftElements(set *nftables.Set, item update) []nftables.SetElement {
	start := nftables.SetElement{Key: item.key, Timeout: item.timeout}
	if !set.Interval {
		return []nftables.SetElement{start}
	}
	// A plain address interval set represents one address as [key, key+1).
	// Match ChinaDNS-NG's netlink encoding explicitly: one ordinary start
	// element followed by an interval-end element. KeyEnd is for concatenated
	// interval keys and is rejected by the kernel for this set shape. nftables
	// attaches per-element timeout only to the start; the kernel rejects a
	// timeout attribute on the interval-end marker.
	return []nftables.SetElement{
		start,
		{Key: nextAddress(item.key), IntervalEnd: true},
	}
}

func nextAddress(key []byte) []byte {
	next := append([]byte(nil), key...)
	for index := len(next) - 1; index >= 0; index-- {
		next[index]++
		if next[index] != 0 {
			break
		}
	}
	return next
}

func (b *netlinkBackend) resolve(ref setRef) (*nftables.Set, error) {
	key := setCacheKey(ref)
	b.mu.RLock()
	set := b.sets[key]
	b.mu.RUnlock()
	if set != nil {
		return set, nil
	}
	set, err := resolveSet(ref)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	if current := b.sets[key]; current != nil {
		set = current
	} else {
		b.sets[key] = set
	}
	b.mu.Unlock()
	return set, nil
}

func (b *netlinkBackend) invalidate(key string, failed *nftables.Set) {
	b.mu.Lock()
	if b.sets[key] == failed {
		delete(b.sets, key)
	}
	b.mu.Unlock()
}

func setCacheKey(ref setRef) string { return ref.String() + fmt.Sprintf("/%d", ref.ipVersion) }

func resolveSet(ref setRef) (*nftables.Set, error) {
	family, err := nftFamily(ref.family)
	if err != nil {
		return nil, err
	}
	table := &nftables.Table{Name: ref.table, Family: family}
	set, err := (&nftables.Conn{}).GetSetByName(table, ref.name)
	if err != nil {
		return nil, fmt.Errorf("DNS result NFTSets: resolve %s: %w", ref.String(), err)
	}
	if set.IsMap {
		return nil, fmt.Errorf("DNS result NFTSets: %s is a map, not a set", ref.String())
	}
	want := nftables.TypeIPAddr.Name
	if ref.ipVersion == 6 {
		want = nftables.TypeIP6Addr.Name
	}
	if set.KeyType.Name != want {
		return nil, fmt.Errorf("DNS result NFTSets: %s has type %s, want %s", ref.String(), set.KeyType.Name, want)
	}
	if !set.HasTimeout {
		return nil, fmt.Errorf("DNS result NFTSets: %s must have the timeout flag", ref.String())
	}
	return set, nil
}

func nftFamily(raw string) (nftables.TableFamily, error) {
	switch raw {
	case "inet":
		return nftables.TableFamilyINet, nil
	case "ip":
		return nftables.TableFamilyIPv4, nil
	case "ip6":
		return nftables.TableFamilyIPv6, nil
	default:
		return 0, fmt.Errorf("DNS result NFTSets: unsupported family %q", raw)
	}
}

func isAlreadyExists(err error) bool {
	return errors.Is(err, unix.EEXIST) || strings.Contains(strings.ToLower(err.Error()), "file exists")
}
