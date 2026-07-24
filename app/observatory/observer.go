// Package observatory implements outbound health probing.
//
// Probing is done with a standalone HTTP client: for each selected outbound the
// probe URL (default https://www.gstatic.com/generate_204) is fetched and the
// round-trip time is recorded as the outbound's delay/alive status. When an
// outbound binds to a local IP, the probe dials through that binding so wan1/
// wan2 probes reflect the real upstream path.
package observatory

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/eugene/bypasscore/app/dialer"
	appoutbound "github.com/eugene/bypasscore/app/outbound"
	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/features/extension"
	"google.golang.org/protobuf/proto"
)

// Observer periodically probes outbounds selected by SubjectSelector and exposes
// the latest results via GetObservation. It implements extension.Observatory.
type Observer struct {
	config *Config
	ctx    context.Context
	cancel context.CancelFunc

	statusLock sync.Mutex
	status     []*OutboundStatus
	history    map[string]*probeHistory
	clientMu   sync.Mutex
	clients    map[string]*http.Client
	startOnce  sync.Once
	wg         sync.WaitGroup

	ohm *appoutbound.Manager
}

const observerHistorySize = 10

type probeHistory struct {
	values []time.Duration // negative values represent failed probes
	next   int
}

func (h *probeHistory) add(value time.Duration) {
	if len(h.values) < observerHistorySize {
		h.values = append(h.values, value)
		return
	}
	h.values[h.next] = value
	h.next = (h.next + 1) % observerHistorySize
}

func (h *probeHistory) stats() *HealthPingMeasurementResult {
	result := &HealthPingMeasurementResult{All: int64(len(h.values))}
	var successful []time.Duration
	for _, value := range h.values {
		if value < 0 {
			result.Fail++
			continue
		}
		successful = append(successful, value)
		if result.Max == 0 || int64(value) > result.Max {
			result.Max = int64(value)
		}
		if result.Min == 0 || int64(value) < result.Min {
			result.Min = int64(value)
		}
		result.Average += int64(value)
	}
	if len(successful) == 0 {
		return result
	}
	result.Average /= int64(len(successful))
	if len(successful) == 1 {
		result.Deviation = result.Average / 2
		return result
	}
	var variance float64
	for _, value := range successful {
		delta := float64(int64(value) - result.Average)
		variance += delta * delta
	}
	result.Deviation = int64(math.Sqrt(variance / float64(len(successful))))
	return result
}

// GetObservation implements extension.Observatory.
func (o *Observer) GetObservation(_ context.Context) (proto.Message, error) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	out := make([]*OutboundStatus, 0, len(o.status))
	for _, status := range o.status {
		out = append(out, proto.Clone(status).(*OutboundStatus))
	}
	return &ObservationResult{Status: out}, nil
}

// Type implements common.HasType.
func (o *Observer) Type() interface{} { return extension.ObservatoryType() }

// Start launches the background probing loop (if SubjectSelector is non-empty).
func (o *Observer) Start() error {
	if o.config == nil || len(o.config.SubjectSelector) == 0 {
		return nil
	}
	o.startOnce.Do(func() {
		o.wg.Add(1)
		go func() {
			defer o.wg.Done()
			o.background()
		}()
	})
	return nil
}

// Close stops the background loop.
func (o *Observer) Close() error {
	if o.cancel != nil {
		o.cancel()
	}
	o.wg.Wait()
	o.clientMu.Lock()
	for tag, client := range o.clients {
		client.CloseIdleConnections()
		delete(o.clients, tag)
	}
	o.clientMu.Unlock()
	return nil
}

func (o *Observer) background() {
	for {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

		outbounds := o.selectOutbounds()
		o.clearRemovedOutbounds(outbounds)

		sleepTime := time.Second * 10
		if o.config.ProbeInterval != 0 {
			sleepTime = time.Duration(o.config.ProbeInterval)
		}

		// Probe every selected outbound (serially or concurrently), then sleep
		// once between rounds. Previously the serial branch slept *between each
		// probe*, so a full round took N×interval; both branches now share the
		// same round-then-sleep cadence.
		if !o.config.EnableConcurrency {
			sort.Strings(outbounds)
			for _, v := range outbounds {
				result := o.probe(v)
				o.updateStatusForResult(v, &result)
			}
		} else {
			var wg sync.WaitGroup
			for _, v := range outbounds {
				wg.Add(1)
				go func(v string) {
					defer wg.Done()
					result := o.probe(v)
					o.updateStatusForResult(v, &result)
				}(v)
			}
			wg.Wait()
		}

		select {
		case <-o.ctx.Done():
			return
		case <-time.After(sleepTime):
		}
	}
}

func (o *Observer) selectOutbounds() []string {
	if o.ohm == nil {
		return nil
	}
	return o.ohm.Select(o.config.SubjectSelector)
}

func (o *Observer) clearRemovedOutbounds(outbounds []string) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	if len(o.status) == 0 {
		return
	}
	active := make(map[string]struct{}, len(outbounds))
	for _, tag := range outbounds {
		active[tag] = struct{}{}
	}
	var pruned []*OutboundStatus
	for _, status := range o.status {
		if _, ok := active[status.OutboundTag]; ok {
			pruned = append(pruned, status)
		}
	}
	o.status = pruned
	for tag := range o.history {
		if _, ok := active[tag]; !ok {
			delete(o.history, tag)
		}
	}
	o.clientMu.Lock()
	for tag, client := range o.clients {
		if _, ok := active[tag]; !ok {
			client.CloseIdleConnections()
			delete(o.clients, tag)
		}
	}
	o.clientMu.Unlock()
}

// probe fetches the probe URL and returns the result. If the outbound binds to
// a local IP, the HTTP client dials through that binding.
func (o *Observer) probe(outboundTag string) ProbeResult {
	probeURL := "https://www.gstatic.com/generate_204"
	if o.config.ProbeUrl != "" {
		probeURL = o.config.ProbeUrl
	}

	client := o.probeClient(outboundTag)
	if client == nil {
		return ProbeResult{Alive: false, LastErrorReason: "outbound dialer not found: " + outboundTag}
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(o.ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return ProbeResult{Alive: false, LastErrorReason: "bad probe url: " + err.Error()}
	}
	req.Header.Set("User-Agent", "BypassCore-Observatory")

	resp, err := client.Do(req)
	if err != nil {
		host := ""
		if u, perr := url.Parse(probeURL); perr == nil {
			host = u.Host
		}
		msg := fmt.Sprintf("outbound %s is dead: GET %s failed: %v", outboundTag, host, err)
		errors.LogDebug(o.ctx, msg)
		return ProbeResult{Alive: false, LastErrorReason: msg}
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	delay := time.Since(start)
	errors.LogDebug(o.ctx, "outbound ", outboundTag, " is alive: ", delay.Seconds())
	return ProbeResult{Alive: true, Delay: delay.Milliseconds()}
}

func (o *Observer) probeClient(outboundTag string) *http.Client {
	o.clientMu.Lock()
	defer o.clientMu.Unlock()
	if client := o.clients[outboundTag]; client != nil {
		return client
	}
	outboundDialer := o.ohm.GetDialer(outboundTag)
	if outboundDialer == nil {
		return nil
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           outboundHTTPDialContext(outboundDialer),
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	o.clients[outboundTag] = client
	return client
}

func outboundHTTPDialContext(outboundDialer dialer.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("unsupported probe network %q", network)
		}
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := bcnet.PortFromString(portText)
		if err != nil {
			return nil, err
		}
		return outboundDialer.Dial(ctx, bcnet.TCPDestination(bcnet.ParseAddress(host), port))
	}
}

// applyBinding configures the dialer to use the outbound's bound local IP.
// (Interface-name → interface-index binding is platform-specific; LocalIP is
// the portable subset of the binding we can always honor.)
func applyBinding(dialer *net.Dialer, bind *appoutbound.BindConfig) {
	if bind == nil || bind.LocalIP == "" {
		return
	}
	if ip := net.ParseIP(bind.LocalIP); ip != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
}

func (o *Observer) updateStatusForResult(outboundTag string, result *ProbeResult) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()

	var status *OutboundStatus
	if loc := o.findStatusLocationLockHolderOnly(outboundTag); loc != -1 {
		status = o.status[loc]
	} else {
		status = &OutboundStatus{}
		o.status = append(o.status, status)
	}

	status.LastTryTime = time.Now().Unix()
	status.OutboundTag = outboundTag
	status.Alive = result.Alive
	if result.Alive {
		status.Delay = result.Delay
		status.LastSeenTime = status.LastTryTime
		status.LastErrorReason = ""
	} else {
		status.LastErrorReason = result.LastErrorReason
		status.Delay = 99999999
	}
	history := o.history[outboundTag]
	if history == nil {
		history = new(probeHistory)
		o.history[outboundTag] = history
	}
	value := -time.Nanosecond
	if result.Alive {
		value = time.Duration(result.Delay) * time.Millisecond
	}
	history.add(value)
	status.HealthPing = history.stats()
}

func (o *Observer) findStatusLocationLockHolderOnly(outboundTag string) int {
	for i, v := range o.status {
		if v.OutboundTag == outboundTag {
			return i
		}
	}
	return -1
}

// New creates an Observer. The context controls the background loop lifetime.
func New(ctx context.Context, config *Config, ohm *appoutbound.Manager) (*Observer, error) {
	if ohm == nil {
		return nil, errors.New("observatory requires an outbound manager")
	}
	subCtx, cancel := context.WithCancel(ctx)
	return &Observer{
		config:  config,
		ctx:     subCtx,
		cancel:  cancel,
		ohm:     ohm,
		history: make(map[string]*probeHistory),
		clients: make(map[string]*http.Client),
	}, nil
}

// Compile-time interface check.
var _ extension.Observatory = (*Observer)(nil)
