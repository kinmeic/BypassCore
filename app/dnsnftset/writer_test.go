package dnsnftset

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	appdns "github.com/eugene/bypasscore/app/dns"
	bcnet "github.com/eugene/bypasscore/common/net"
)

type fakeBackend struct {
	mu       sync.Mutex
	probes   int
	updates  []update
	batches  []int
	err      error
	existing bool
}

func (f *fakeBackend) Probe([]setRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes++
	return f.err
}

func (f *fakeBackend) Add(updates []update) []writeResult {
	f.mu.Lock()
	f.batches = append(f.batches, len(updates))
	for _, item := range updates {
		item.key = append([]byte(nil), item.key...)
		f.updates = append(f.updates, item)
	}
	existing := f.existing
	f.mu.Unlock()
	results := make([]writeResult, len(updates))
	for i := range results {
		if existing {
			results[i].existing = true
		} else {
			results[i].applied = true
		}
	}
	return results
}

func TestWriterTemporarilySuppressesRepeatedExistingElements(t *testing.T) {
	backend := &fakeBackend{existing: true}
	writer, err := newWithBackend(&Config{
		QueueSize: 4, BatchSize: 1, FlushIntervalMs: 1,
		Policies: []Policy{{ServerTags: []string{"direct"}, IPv4Set: "inet@bypass@direct4"}},
	}, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Probe(); err != nil {
		t.Fatal(err)
	}
	result := appdns.Result{ServerTag: "direct", TTL: 60, IPs: []bcnet.IP{bcnet.IP(net.ParseIP("192.0.2.1").To4())}}
	writer.Emit(result)
	deadline := time.Now().Add(time.Second)
	for writer.Status().Existing == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	writer.Emit(result)
	time.Sleep(20 * time.Millisecond)
	backend.mu.Lock()
	writes := len(backend.updates)
	backend.mu.Unlock()
	if writes != 1 || writer.Status().Deduplicated == 0 {
		t.Fatalf("writes=%d status=%#v", writes, writer.Status())
	}
}

func TestWriterFiltersUnsafeDNSResultAddresses(t *testing.T) {
	backend := new(fakeBackend)
	writer, err := newWithBackend(&Config{
		QueueSize: 4, BatchSize: 16, FlushIntervalMs: 1,
		Policies: []Policy{{ServerTags: []string{"direct"}, IPv4Set: "inet@bypass@direct4", IPv6Set: "inet@bypass@direct6"}},
	}, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	writer.Emit(appdns.Result{
		ServerTag: "direct", TTL: 60,
		IPs: []bcnet.IP{
			bcnet.IP(net.ParseIP("0.1.2.3").To4()),
			bcnet.IP(net.ParseIP("127.0.0.1").To4()),
			bcnet.IP(net.ParseIP("::").To16()),
			bcnet.IP(net.ParseIP("::1").To16()),
			bcnet.IP(net.ParseIP("192.0.2.1").To4()),
		},
	})
	deadline := time.Now().Add(time.Second)
	for writer.Status().Applied != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	backend.mu.Lock()
	writes := append([]update(nil), backend.updates...)
	backend.mu.Unlock()
	if len(writes) != 1 || net.IP(writes[0].key).String() != "192.0.2.1" {
		t.Fatalf("unexpected writes: %#v", writes)
	}
	if status := writer.Status(); status.Filtered != 4 {
		t.Fatalf("filtered=%d, want 4 (%#v)", status.Filtered, status)
	}
}

func TestSuccessfulProbeInvalidatesWriterDedupe(t *testing.T) {
	backend := new(fakeBackend)
	writer, err := newWithBackend(&Config{
		QueueSize: 4, BatchSize: 1, FlushIntervalMs: 1,
		Policies: []Policy{{ServerTags: []string{"direct"}, IPv4Set: "inet@bypass@direct4"}},
	}, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Probe(); err != nil {
		t.Fatal(err)
	}
	result := appdns.Result{ServerTag: "direct", TTL: 60, IPs: []bcnet.IP{bcnet.IP(net.ParseIP("192.0.2.1").To4())}}
	writer.Emit(result)
	deadline := time.Now().Add(time.Second)
	for writer.Status().Applied != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	writer.Emit(result)
	time.Sleep(20 * time.Millisecond)
	if status := writer.Status(); status.Applied != 1 || status.Deduplicated == 0 {
		t.Fatalf("duplicate was not suppressed before reprobe: %#v", status)
	}

	backend.mu.Lock()
	backend.err = errors.New("temporary probe failure")
	backend.mu.Unlock()
	if err := writer.Probe(); err == nil {
		t.Fatal("failed probe unexpectedly succeeded")
	}
	writer.Emit(result)
	time.Sleep(20 * time.Millisecond)
	if status := writer.Status(); status.Applied != 1 {
		t.Fatalf("failed probe invalidated dedupe: %#v", status)
	}

	backend.mu.Lock()
	backend.err = nil
	backend.mu.Unlock()
	if err := writer.Probe(); err != nil {
		t.Fatal(err)
	}
	writer.Emit(result)
	deadline = time.Now().Add(time.Second)
	for writer.Status().Applied != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if status := writer.Status(); status.Applied != 2 || !status.Ready {
		t.Fatalf("successful reprobe did not permit repopulation: %#v", status)
	}
}

func TestWriterEnforcesNetlinkBatchSize(t *testing.T) {
	backend := new(fakeBackend)
	writer, err := newWithBackend(&Config{
		QueueSize: 2, BatchSize: 3, FlushIntervalMs: 1,
		Policies: []Policy{{ServerTags: []string{"direct"}, IPv4Set: "inet@bypass@direct4"}},
	}, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Probe(); err != nil {
		t.Fatal(err)
	}
	result := appdns.Result{ServerTag: "direct", TTL: 60}
	for last := 1; last <= 10; last++ {
		result.IPs = append(result.IPs, bcnet.IP(net.IPv4(192, 0, 2, byte(last)).To4()))
	}
	writer.Emit(result)
	deadline := time.Now().Add(time.Second)
	for writer.Status().Applied != 10 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.batches) != 4 {
		t.Fatalf("batch count=%d, want 4 (%v)", len(backend.batches), backend.batches)
	}
	for _, size := range backend.batches {
		if size < 1 || size > 3 {
			t.Fatalf("batch exceeded configured size: %v", backend.batches)
		}
	}
}

func TestNormalizeConfig(t *testing.T) {
	config, err := NormalizeConfig(&Config{Policies: []Policy{{ServerTags: []string{"direct"}, IPv4Set: "inet@bypass@direct4", IPv6Set: "inet@bypass@direct6"}}})
	if err != nil {
		t.Fatal(err)
	}
	if config.QueueSize != defaultQueueSize || config.BatchSize != defaultBatchSize || config.FlushIntervalMs != defaultFlushIntervalMs {
		t.Fatalf("unexpected defaults: %#v", config)
	}
	bad := []Config{
		{},
		{Policies: []Policy{{ServerTags: []string{""}, IPv4Set: "inet@bypass@direct4"}}},
		{Policies: []Policy{{ServerTags: []string{"x"}, IPv4Set: "ip6@bypass@direct4"}}},
		{Policies: []Policy{{ServerTags: []string{"x"}, IPv6Set: "inet@bad name@direct6"}}},
	}
	for i := range bad {
		if err := Validate(&bad[i]); err == nil {
			t.Fatalf("invalid config %d was accepted", i)
		}
	}
}

func TestWriterFiltersFamiliesDeduplicatesAndProbes(t *testing.T) {
	backend := new(fakeBackend)
	writer, err := newWithBackend(&Config{
		QueueSize: 4, BatchSize: 32, FlushIntervalMs: 5,
		Policies: []Policy{{ServerTags: []string{"direct"}, IPv4Set: "inet@bypass@direct4", IPv6Set: "inet@bypass@direct6"}},
	}, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Probe(); err != nil {
		t.Fatal(err)
	}
	writer.Emit(appdns.Result{
		Domain: "example.test", ServerTag: "direct", TTL: 60,
		IPs: []bcnet.IP{bcnet.IP(net.ParseIP("192.0.2.1").To4()), bcnet.IP(net.ParseIP("2001:db8::1").To16())},
	})
	writer.Emit(appdns.Result{
		Domain: "example.test", ServerTag: "direct", TTL: 60,
		IPs: []bcnet.IP{bcnet.IP(net.ParseIP("192.0.2.1").To4())},
	})
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		backend.mu.Lock()
		count := len(backend.updates)
		backend.mu.Unlock()
		if count == 2 && writer.Status().Applied == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.probes != 1 || len(backend.updates) != 2 {
		t.Fatalf("probes=%d updates=%d", backend.probes, len(backend.updates))
	}
	for _, item := range backend.updates {
		if item.timeout != 60*time.Second {
			t.Fatalf("unexpected timeout: %v", item.timeout)
		}
		if item.set.ipVersion == 4 && net.IP(item.key).String() != "192.0.2.1" {
			t.Fatalf("unexpected IPv4 key: %v", item.key)
		}
		if item.set.ipVersion == 6 && net.IP(item.key).String() != "2001:db8::1" {
			t.Fatalf("unexpected IPv6 key: %v", item.key)
		}
	}
	status := writer.Status()
	if !status.Ready || !status.Probed || status.Applied != 2 || status.Deduplicated == 0 {
		t.Fatalf("unexpected status: %#v", status)
	}
}

func TestWriterRequiresSuccessfulProbeForReadiness(t *testing.T) {
	backend := &fakeBackend{err: errors.New("set is missing")}
	writer, err := newWithBackend(&Config{
		QueueSize: 2, BatchSize: 1, FlushIntervalMs: 1,
		Policies: []Policy{{ServerTags: []string{"direct"}, IPv4Set: "inet@bypass@direct4"}},
	}, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if status := writer.Status(); status.Ready || status.Probed {
		t.Fatalf("unprobed writer reported ready: %#v", status)
	}
	if err := writer.Probe(); err == nil {
		t.Fatal("failed target probe unexpectedly succeeded")
	}
	writer.Emit(appdns.Result{ServerTag: "direct", TTL: 60, IPs: []bcnet.IP{bcnet.IP(net.ParseIP("192.0.2.1").To4())}})
	deadline := time.Now().Add(time.Second)
	for writer.Status().Applied == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if status := writer.Status(); status.Ready || !status.Probed {
		t.Fatalf("a partial write overrode a failed full probe: %#v", status)
	}
	backend.mu.Lock()
	backend.err = nil
	backend.mu.Unlock()
	if err := writer.Probe(); err != nil {
		t.Fatal(err)
	}
	if status := writer.Status(); !status.Ready || !status.Probed {
		t.Fatalf("successful full probe did not restore readiness: %#v", status)
	}
}
