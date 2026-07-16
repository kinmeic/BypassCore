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
	number atomic.Int64
}

var registry sync.Map // canonical key -> *value

func metric(name string, labelPairs ...string) *value {
	labels := canonicalLabels(labelPairs)
	key := name + "\x00" + labels
	if existing, ok := registry.Load(key); ok {
		return existing.(*value)
	}
	created := &value{name: name, labels: labels}
	actual, _ := registry.LoadOrStore(key, created)
	return actual.(*value)
}

func Inc(name string, labelPairs ...string) { metric(name, labelPairs...).number.Add(1) }
func Add(name string, delta int64, labelPairs ...string) {
	metric(name, labelPairs...).number.Add(delta)
}
func Set(name string, current int64, labelPairs ...string) {
	metric(name, labelPairs...).number.Store(current)
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
}
