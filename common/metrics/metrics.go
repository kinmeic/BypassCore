// Package metrics provides a tiny dependency-free process-wide metric
// registry for hot-path counters and gauges.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type value struct {
	name   string
	labels string
	values map[string]string
	number atomic.Int64
}

// Handle resolves and validates a metric series once, allowing hot paths to
// update the underlying atomic value without rebuilding and sorting labels.
type Handle struct {
	item *value
}

// NewHandle resolves a low-cardinality metric series.
func NewHandle(name string, labelPairs ...string) *Handle {
	return &Handle{item: metric(name, labelPairs...)}
}

// Add atomically adjusts the resolved series. A nil/restricted series is a
// no-op.
func (h *Handle) Add(delta int64) {
	if h != nil && h.item != nil {
		h.item.number.Add(delta)
	}
}

// Set atomically stores the value of the resolved series.
func (h *Handle) Set(current int64) {
	if h != nil && h.item != nil {
		h.item.number.Store(current)
	}
}

var registry sync.Map // canonical key -> *value
var restrictions atomic.Pointer[labelRestrictions]

type labelRestrictions struct {
	allowed map[string]map[string]struct{}
}

func metric(name string, labelPairs ...string) *value {
	values := labelValues(labelPairs)
	current := restrictions.Load()
	if current != nil && !labelsAllowed(values, current.allowed) {
		return nil
	}
	labels := canonicalLabels(labelPairs)
	key := name + "\x00" + labels
	if existing, ok := registry.Load(key); ok {
		return existing.(*value)
	}
	created := &value{name: name, labels: labels, values: values}
	actual, _ := registry.LoadOrStore(key, created)
	// A reload may replace restrictions between the first check and insertion.
	// Recheck after LoadOrStore so a retired snapshot cannot recreate a pruned
	// low-cardinality series after RetainLabelValues has already scanned it.
	if latest := restrictions.Load(); latest != current && latest != nil && !labelsAllowed(values, latest.allowed) {
		registry.Delete(key)
		return nil
	}
	return actual.(*value)
}

func labelsAllowed(values map[string]string, allowed map[string]map[string]struct{}) bool {
	for label, choices := range allowed {
		if current, exists := values[label]; exists {
			if _, ok := choices[current]; !ok {
				return false
			}
		}
	}
	return true
}

func labelValues(pairs []string) map[string]string {
	if len(pairs) == 0 {
		return nil
	}
	values := make(map[string]string, len(pairs)/2)
	for index := 0; index+1 < len(pairs); index += 2 {
		values[pairs[index]] = pairs[index+1]
	}
	return values
}

func Inc(name string, labelPairs ...string) {
	if item := metric(name, labelPairs...); item != nil {
		item.number.Add(1)
	}
}
func Add(name string, delta int64, labelPairs ...string) {
	if item := metric(name, labelPairs...); item != nil {
		item.number.Add(delta)
	}
}
func Set(name string, current int64, labelPairs ...string) {
	if item := metric(name, labelPairs...); item != nil {
		item.number.Store(current)
	}
}

type Sample struct {
	Name   string
	Labels string
	Value  int64
}

func Snapshot() []Sample {
	samples := make([]Sample, 0)
	registry.Range(func(_, raw any) bool {
		item := raw.(*value)
		samples = append(samples, Sample{Name: item.name, Labels: item.labels, Value: item.number.Load()})
		return true
	})
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].Name == samples[j].Name {
			return samples[i].Labels < samples[j].Labels
		}
		return samples[i].Name < samples[j].Name
	})
	return samples
}

func WritePrometheus(writer io.Writer) error {
	for _, sample := range Snapshot() {
		if _, err := fmt.Fprintf(writer, "%s%s %d\n", sample.Name, sample.Labels, sample.Value); err != nil {
			return err
		}
	}
	return nil
}

func canonicalLabels(pairs []string) string {
	if len(pairs) == 0 {
		return ""
	}
	type pair struct{ name, value string }
	items := make([]pair, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		items = append(items, pair{name: pairs[i], value: pairs[i+1]})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	var builder strings.Builder
	builder.WriteByte('{')
	for i, item := range items {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(item.name)
		builder.WriteByte('=')
		builder.WriteString(strconv.Quote(item.value))
	}
	builder.WriteByte('}')
	return builder.String()
}

func ResetForTest() {
	registry.Range(func(key, _ any) bool {
		registry.Delete(key)
		return true
	})
	restrictions.Store(nil)
}

// RetainLabelValues removes series whose controlled labels no longer exist in
// the active configuration. This bounds cardinality across repeated reloads.
func RetainLabelValues(allowed map[string]map[string]struct{}) {
	copyAllowed := make(map[string]map[string]struct{}, len(allowed))
	for label, values := range allowed {
		copyValues := make(map[string]struct{}, len(values))
		for value := range values {
			copyValues[value] = struct{}{}
		}
		copyAllowed[label] = copyValues
	}
	restrictions.Store(&labelRestrictions{allowed: copyAllowed})
	registry.Range(func(key, raw any) bool {
		item := raw.(*value)
		for label, values := range copyAllowed {
			if current, exists := item.values[label]; exists {
				if _, keep := values[current]; !keep {
					registry.Delete(key)
					break
				}
			}
		}
		return true
	})
}
