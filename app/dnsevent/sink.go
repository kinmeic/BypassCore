// Package dnsevent emits successful A/AAAA resolution results to a local Unix
// datagram consumer without ever blocking DNS request processing.
package dnsevent

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	appdns "github.com/eugene/bypasscore/app/dns"
	commonmetrics "github.com/eugene/bypasscore/common/metrics"
)

type Config struct {
	Socket           string `json:"socket"`
	QueueSize        int    `json:"queueSize,omitempty"`
	MaxDatagramBytes int    `json:"maxDatagramBytes,omitempty"`
	MaxQueueBytes    int64  `json:"maxQueueBytes,omitempty"`
}

type Event struct {
	Sequence       uint64   `json:"sequence"`
	ConfigRevision uint64   `json:"configRevision"`
	Domain         string   `json:"domain"`
	IPs            []string `json:"ips"`
	TTL            uint32   `json:"ttl"`
	ServerTag      string   `json:"serverTag"`
	Timestamp      int64    `json:"timestamp"`
	ExpiresAt      int64    `json:"expiresAt"`
	DroppedBefore  uint64   `json:"droppedBefore"`
}

type Stats struct {
	QueuedBytes int64  `json:"queuedBytes"`
	Dropped     uint64 `json:"dropped"`
}

type Sink struct {
	config  Config
	queue   chan []byte
	done    chan struct{}
	mu      sync.RWMutex
	closed  bool
	wg      sync.WaitGroup
	queued  atomic.Int64
	dropped atomic.Uint64
}

// NormalizeConfig validates the sink without allocating runtime resources.
func NormalizeConfig(config *Config) (Config, error) {
	if config == nil {
		return Config{}, errors.New("DNS result events: nil config")
	}
	c := *config
	if strings.TrimSpace(c.Socket) == "" || !filepath.IsAbs(c.Socket) {
		return Config{}, errors.New("DNS result events: socket must be an absolute path")
	}
	if c.QueueSize == 0 {
		c.QueueSize = 256
	}
	if c.QueueSize < 1 || c.QueueSize > 4096 {
		return Config{}, errors.New("DNS result events: queueSize must be between 1 and 4096")
	}
	if c.MaxDatagramBytes == 0 {
		c.MaxDatagramBytes = 8192
	}
	if c.MaxDatagramBytes < 512 || c.MaxDatagramBytes > 32768 {
		return Config{}, errors.New("DNS result events: maxDatagramBytes must be between 512 and 32768")
	}
	if c.MaxQueueBytes == 0 {
		c.MaxQueueBytes = 1 << 20
	}
	if c.MaxQueueBytes < int64(c.MaxDatagramBytes) || c.MaxQueueBytes > 8<<20 {
		return Config{}, errors.New("DNS result events: maxQueueBytes must be between maxDatagramBytes and 8 MiB")
	}
	return c, nil
}

func Validate(config *Config) error { _, err := NormalizeConfig(config); return err }

func New(config *Config) (*Sink, error) {
	c, err := NormalizeConfig(config)
	if err != nil {
		return nil, err
	}
	s := &Sink{config: c, queue: make(chan []byte, c.QueueSize), done: make(chan struct{})}
	s.wg.Add(1)
	go s.run()
	return s, nil
}

func (s *Sink) Emit(result appdns.Result) {
	s.EmitEvent(NewEvent(result, 0, 0))
}

func NewEvent(result appdns.Result, revision, sequence uint64) Event {
	event := Event{Sequence: sequence, ConfigRevision: revision, Domain: result.Domain, TTL: result.TTL, ServerTag: result.ServerTag, Timestamp: result.At.Unix(), ExpiresAt: result.At.Add(time.Duration(result.TTL) * time.Second).Unix()}
	for _, ip := range result.IPs {
		event.IPs = append(event.IPs, ip.String())
	}
	return event
}

func (s *Sink) EmitEvent(event Event) {
	event.DroppedBefore = s.dropped.Load()
	payload, err := json.Marshal(event)
	if err != nil || len(payload) > s.config.MaxDatagramBytes {
		s.dropped.Add(1)
		commonmetrics.Inc("bypasscore_dns_result_events_total", "result", "oversize")
		return
	}
	size := int64(len(payload))
	for {
		queued := s.queued.Load()
		if queued+size > s.config.MaxQueueBytes {
			s.dropped.Add(1)
			commonmetrics.Inc("bypasscore_dns_result_events_total", "result", "dropped_bytes")
			return
		}
		if s.queued.CompareAndSwap(queued, queued+size) {
			break
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		s.queued.Add(-size)
		return
	}
	select {
	case s.queue <- payload:
	default:
		s.queued.Add(-size)
		s.dropped.Add(1)
		commonmetrics.Inc("bypasscore_dns_result_events_total", "result", "dropped")
	}
}

func (s *Sink) Stats() Stats { return Stats{QueuedBytes: s.queued.Load(), Dropped: s.dropped.Load()} }

func (s *Sink) run() {
	defer s.wg.Done()
	address := &net.UnixAddr{Name: s.config.Socket, Net: "unixgram"}
	var conn *net.UnixConn
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	for {
		select {
		case <-s.done:
			return
		default:
		}
		var payload []byte
		select {
		case <-s.done:
			return
		case payload = <-s.queue:
			s.queued.Add(-int64(len(payload)))
		}
		var err error
		if conn == nil {
			conn, err = net.DialUnix("unixgram", nil, address)
		}
		if err == nil && conn != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			_, err = conn.Write(payload)
		}
		if err != nil && conn != nil {
			_ = conn.Close()
			conn = nil
		}
		result := "sent"
		if err != nil {
			result = "error"
		}
		commonmetrics.Inc("bypasscore_dns_result_events_total", "result", result)
	}
}

func (s *Sink) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.done)
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}
