package dnsnftset

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	appdns "github.com/eugene/bypasscore/app/dns"
	commonmetrics "github.com/eugene/bypasscore/common/metrics"
)

type update struct {
	set     setRef
	key     []byte
	timeout time.Duration
}

type backend interface {
	Probe([]setRef) error
	Add([]update) []writeResult
}

type queuedResult struct{ updates []update }

type writeResult struct {
	err      error
	added    bool
	existing bool
}

// Stats is a bounded runtime snapshot suitable for status/control responses.
type Stats struct {
	Enabled      bool      `json:"enabled"`
	Ready        bool      `json:"ready"`
	Probed       bool      `json:"probed"`
	Policies     int       `json:"policies"`
	Targets      int       `json:"targets"`
	Queued       int64     `json:"queued"`
	Dropped      uint64    `json:"dropped"`
	Filtered     uint64    `json:"filtered"`
	Added        uint64    `json:"added"`
	Existing     uint64    `json:"existing"`
	Deduplicated uint64    `json:"deduplicated"`
	Errors       uint64    `json:"errors"`
	LastSuccess  time.Time `json:"lastSuccess,omitempty"`
	LastError    string    `json:"lastError,omitempty"`
}

// Writer asynchronously coalesces DNS results and writes them with their DNS
// TTL as an nftables element timeout. Emit never blocks the DNS request path.
type Writer struct {
	config          Config
	backend         backend
	targetsByTag    map[string][]setRef
	targets         []setRef
	queue           chan queuedResult
	done            chan struct{}
	mu              sync.RWMutex
	closed          bool
	closeOnce       sync.Once
	wg              sync.WaitGroup
	queued          atomic.Int64
	dropped         atomic.Uint64
	filtered        atomic.Uint64
	added           atomic.Uint64
	existing        atomic.Uint64
	deduplicated    atomic.Uint64
	errors          atomic.Uint64
	probeGeneration atomic.Uint64
	statusMu        sync.RWMutex
	probed          bool
	probeHealthy    bool
	writeHealthy    bool
	ready           bool
	lastSuccess     time.Time
	lastError       string
}

// New builds a writer. Target-set existence is checked later by Probe so a
// supervisor can create its nftables table after starting BypassCore.
func New(config *Config) (*Writer, error) { return newWithBackend(config, newBackend()) }

func newWithBackend(config *Config, implementation backend) (*Writer, error) {
	c, err := NormalizeConfig(config)
	if err != nil {
		return nil, err
	}
	if implementation == nil {
		return nil, errors.New("DNS result NFTSets: nil backend")
	}
	w := &Writer{
		config: c, backend: implementation, targetsByTag: make(map[string][]setRef),
		queue: make(chan queuedResult, c.QueueSize), done: make(chan struct{}), writeHealthy: true,
	}
	uniqueTargets := make(map[string]setRef)
	for _, policy := range c.Policies {
		var refs []setRef
		if policy.IPv4Set != "" {
			ref, _ := parseSetRef(policy.IPv4Set, 4)
			refs = append(refs, ref)
			uniqueTargets[ref.String()+"/4"] = ref
		}
		if policy.IPv6Set != "" {
			ref, _ := parseSetRef(policy.IPv6Set, 6)
			refs = append(refs, ref)
			uniqueTargets[ref.String()+"/6"] = ref
		}
		for _, tag := range policy.ServerTags {
			for _, ref := range refs {
				if !containsSetRef(w.targetsByTag[tag], ref) {
					w.targetsByTag[tag] = append(w.targetsByTag[tag], ref)
				}
			}
		}
	}
	keys := make([]string, 0, len(uniqueTargets))
	for key := range uniqueTargets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		w.targets = append(w.targets, uniqueTargets[key])
	}
	w.wg.Add(1)
	go w.run()
	return w, nil
}

func containsSetRef(refs []setRef, candidate setRef) bool {
	for _, ref := range refs {
		if ref == candidate {
			return true
		}
	}
	return false
}

// Emit queues one successful DNS result without blocking.
func (w *Writer) Emit(result appdns.Result) {
	refs := w.targetsByTag[result.ServerTag]
	if len(refs) == 0 || len(result.IPs) == 0 {
		return
	}
	ttl := time.Duration(result.TTL) * time.Second
	if ttl <= 0 {
		ttl = time.Second
	}
	updates := make([]update, 0, len(refs)*len(result.IPs))
	for _, raw := range result.IPs {
		ip := net.IP(raw)
		if unsafeDNSResultIP(ip) {
			w.filtered.Add(1)
			commonmetrics.Inc("bypasscore_dns_nftset_results_total", "result", "filtered")
			continue
		}
		for _, ref := range refs {
			var key []byte
			if ref.ipVersion == 4 {
				key = ip.To4()
			} else if ip.To4() == nil {
				key = ip.To16()
			}
			if key != nil {
				updates = append(updates, update{set: ref, key: append([]byte(nil), key...), timeout: ttl})
			}
		}
	}
	if len(updates) == 0 {
		return
	}

	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return
	}
	select {
	case w.queue <- queuedResult{updates: updates}:
		w.queued.Add(1)
	default:
		w.dropped.Add(1)
		commonmetrics.Inc("bypasscore_dns_nftset_results_total", "result", "dropped")
	}
}

// unsafeDNSResultIP matches ChinaDNS-NG's default add-IP blacklist. Loopback
// and unspecified answers must never become routing or recursion exemptions.
func unsafeDNSResultIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 0 || v4[0] == 127
	}
	v6 := ip.To16()
	return v6 != nil && (net.IP(v6).IsUnspecified() || net.IP(v6).IsLoopback())
}

// Probe verifies that every configured set exists, has the expected address
// datatype, and supports per-element timeouts.
func (w *Writer) Probe() error {
	err := w.backend.Probe(w.targets)
	if err == nil {
		// The sets are externally owned and may have been flushed or recreated
		// since the previous probe. Invalidate the writer-side TTL cache so the
		// next accepted DNS result can repopulate the current kernel objects.
		w.probeGeneration.Add(1)
	}
	w.recordProbeHealth(err)
	return err
}

// Status reports queue, write, and target health.
func (w *Writer) Status() Stats {
	w.statusMu.RLock()
	status := Stats{
		Enabled: true, Ready: w.ready, Probed: w.probed, Policies: len(w.config.Policies), Targets: len(w.targets),
		Queued: w.queued.Load(), Dropped: w.dropped.Load(), Filtered: w.filtered.Load(), Added: w.added.Load(), Existing: w.existing.Load(),
		Deduplicated: w.deduplicated.Load(), Errors: w.errors.Load(), LastSuccess: w.lastSuccess, LastError: w.lastError,
	}
	w.statusMu.RUnlock()
	return status
}

func (w *Writer) recordProbeHealth(err error) {
	w.statusMu.Lock()
	w.probed = true
	w.probeHealthy = err == nil
	if err == nil {
		w.lastSuccess = time.Now()
	} else {
		w.lastError = err.Error()
	}
	w.ready = w.probeHealthy && w.writeHealthy
	if w.ready {
		w.lastError = ""
	}
	w.statusMu.Unlock()
}

func (w *Writer) recordWriteHealth(err error) {
	w.statusMu.Lock()
	w.writeHealthy = err == nil
	if err == nil {
		w.lastSuccess = time.Now()
	} else {
		w.lastError = err.Error()
	}
	w.ready = w.probeHealthy && w.writeHealthy
	if w.ready {
		w.lastError = ""
	}
	w.statusMu.Unlock()
}

func (w *Writer) run() {
	defer w.wg.Done()
	interval := time.Duration(w.config.FlushIntervalMs) * time.Millisecond
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	var timerC <-chan time.Time
	var pending []update
	known := make(map[string]time.Time)
	knownGeneration := w.probeGeneration.Load()
	flush := func(all bool) {
		for len(pending) >= w.config.BatchSize || all && len(pending) > 0 {
			if generation := w.probeGeneration.Load(); generation != knownGeneration {
				clear(known)
				knownGeneration = generation
			}
			count := min(len(pending), w.config.BatchSize)
			w.flush(pending[:count], known)
			pending = pending[count:]
		}
		if len(pending) == 0 {
			// Do not retain an unusually large DNS response for the writer's
			// lifetime after all of its bounded netlink batches have drained.
			pending = nil
		}
	}
	resetTimer := func() {
		if timerC == nil {
			timer.Reset(interval)
			timerC = timer.C
		}
	}
	stopTimer := func() {
		if timerC != nil && !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
	}

	for {
		select {
		case item := <-w.queue:
			w.queued.Add(-1)
			pending = append(pending, item.updates...)
			if len(pending) >= w.config.BatchSize {
				stopTimer()
				flush(false)
				if len(pending) > 0 {
					resetTimer()
				}
			} else {
				resetTimer()
			}
		case <-timerC:
			timerC = nil
			flush(true)
		case <-w.done:
			stopTimer()
			for {
				select {
				case item := <-w.queue:
					w.queued.Add(-1)
					pending = append(pending, item.updates...)
				default:
					flush(true)
					return
				}
			}
		}
	}
}

func (w *Writer) flush(raw []update, known map[string]time.Time) {
	now := time.Now()
	unique := make([]update, 0, len(raw))
	indices := make(map[string]int, len(raw))
	keys := make([]string, 0, len(raw))
	for _, candidate := range raw {
		key := candidate.set.String() + "/" + fmt.Sprint(candidate.set.ipVersion) + "/" + string(candidate.key)
		if expiry, exists := known[key]; exists && expiry.After(now) {
			w.deduplicated.Add(1)
			continue
		}
		if index, exists := indices[key]; exists {
			if candidate.timeout > unique[index].timeout {
				unique[index].timeout = candidate.timeout
			}
			w.deduplicated.Add(1)
			continue
		}
		indices[key] = len(unique)
		keys = append(keys, key)
		unique = append(unique, candidate)
	}
	if len(unique) == 0 {
		return
	}
	results := w.backend.Add(unique)
	if len(results) != len(unique) {
		results = make([]writeResult, len(unique))
		for i := range results {
			results[i].err = errors.New("DNS result NFTSets: backend returned an invalid result count")
		}
	}
	var failures []error
	seenFailures := make(map[string]struct{})
	for i, result := range results {
		if result.err == nil && result.added {
			known[keys[i]] = now.Add(unique[i].timeout)
			w.added.Add(1)
			commonmetrics.Inc("bypasscore_dns_nftset_elements_total", "result", "added", "set", unique[i].set.String())
			continue
		}
		if result.err == nil && result.existing {
			// Do not assume that a pre-existing element has the requested TTL. It
			// may belong to a retiring writer and be close to expiry. A short
			// suppression window still prevents a popular static/range element
			// from forcing an EEXIST retry transaction on every cached DNS answer.
			known[keys[i]] = now.Add(time.Second)
			w.existing.Add(1)
			commonmetrics.Inc("bypasscore_dns_nftset_elements_total", "result", "existing", "set", unique[i].set.String())
			continue
		}
		if result.err == nil {
			result.err = errors.New("DNS result NFTSets: backend returned an empty write result")
		}
		w.errors.Add(1)
		if message := result.err.Error(); message != "" {
			if _, exists := seenFailures[message]; !exists {
				seenFailures[message] = struct{}{}
				failures = append(failures, result.err)
			}
		}
		commonmetrics.Inc("bypasscore_dns_nftset_elements_total", "result", "error", "set", unique[i].set.String())
	}
	if len(failures) == 0 {
		w.recordWriteHealth(nil)
	} else {
		w.recordWriteHealth(errors.Join(failures...))
	}
	// Bound the dedupe map even when upstreams return many one-shot addresses.
	const maxKnownElements = 65536
	if len(known) > maxKnownElements {
		for key, expiry := range known {
			if !expiry.After(now) {
				delete(known, key)
			}
		}
		for key := range known {
			if len(known) <= maxKnownElements {
				break
			}
			delete(known, key)
		}
	}
}

// Close drains queued results and stops the writer.
func (w *Writer) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		close(w.done)
		w.mu.Unlock()
		w.wg.Wait()
	})
	return nil
}
