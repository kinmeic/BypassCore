//go:build !linux

package dnsnftset

import "errors"

type unsupportedBackend struct{}

func newBackend() backend { return unsupportedBackend{} }

func (unsupportedBackend) Probe([]setRef) error {
	return errors.New("DNS result NFTSets: nftables netlink is only available on Linux")
}

func (unsupportedBackend) Add(updates []update) []writeResult {
	results := make([]writeResult, len(updates))
	for i := range results {
		results[i].err = errors.New("DNS result NFTSets: nftables netlink is only available on Linux")
	}
	return results
}
