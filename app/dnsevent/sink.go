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
	"time"

	appdns "github.com/eugene/bypasscore/app/dns"
	commonmetrics "github.com/eugene/bypasscore/common/metrics"
)

type Config struct {
	Socket           string `json:"socket"`
	QueueSize        int    `json:"queueSize,omitempty"`
	MaxDatagramBytes int    `json:"maxDatagramBytes,omitempty"`
}

type Event struct {
	Domain    string   `json:"domain"`
	IPs       []string `json:"ips"`
	TTL       uint32   `json:"ttl"`
	ServerTag string   `json:"serverTag"`
	Timestamp int64    `json:"timestamp"`
}

type Sink struct {
	config Config
	queue  chan []byte
	done   chan struct{}
	mu     sync.RWMutex
	closed bool
	wg     sync.WaitGroup
}

func New(config *Config) (*Sink, error) {
	if config == nil {
		return nil, errors.New("DNS result events: nil config")
	}
	c := *config
	if strings.TrimSpace(c.Socket) == "" || !filepath.IsAbs(c.Socket) {
		return nil, errors.New("DNS result events: socket must be an absolute path")
	}
	if c.QueueSize == 0 {
		c.QueueSize = 1024
	}
	if c.QueueSize < 1 || c.QueueSize > 65536 {
		return nil, errors.New("DNS result events: queueSize must be between 1 and 65536")
	}
	if c.MaxDatagramBytes == 0 {
		c.MaxDatagramBytes = 8192
	}
	if c.MaxDatagramBytes < 512 || c.MaxDatagramBytes > 65507 {
		return nil, errors.New("DNS result events: maxDatagramBytes must be between 512 and 65507")
	}
	s := &Sink{config: c, queue: make(chan []byte, c.QueueSize), done: make(chan struct{})}
	s.wg.Add(1)
	go s.run()
	return s, nil
}

func (s *Sink) Emit(result appdns.Result) {
	event := Event{Domain: result.Domain, TTL: result.TTL, ServerTag: result.ServerTag, Timestamp: result.At.Unix()}
	for _, ip := range result.IPs {
		event.IPs = append(event.IPs, ip.String())
	}
	payload, err := json.Marshal(event)
	if err != nil || len(payload) > s.config.MaxDatagramBytes {
		commonmetrics.Inc("bypasscore_dns_result_events_total", "result", "oversize")
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return
	}
	select {
	case s.queue <- payload:
	default:
		commonmetrics.Inc("bypasscore_dns_result_events_total", "result", "dropped")
	}
}

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
