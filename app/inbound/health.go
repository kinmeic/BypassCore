package inbound

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
)

type HealthStatus struct {
	Tag       string    `json:"tag"`
	State     string    `json:"state"`
	LastError string    `json:"lastError,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type healthTracker struct {
	mu         sync.RWMutex
	status     HealthStatus
	failures   chan error
	components map[string]componentHealth
}

type componentHealth struct {
	state string
	err   string
}

func newHealthTracker(tag string) *healthTracker {
	return &healthTracker{status: HealthStatus{Tag: tag, State: "new", UpdatedAt: time.Now()}, failures: make(chan error, 1), components: make(map[string]componentHealth)}
}

func (h *healthTracker) set(tag, state string, err error, notify bool) {
	h.mu.Lock()
	h.status.Tag = tag
	h.status.State = state
	h.status.UpdatedAt = time.Now()
	if err != nil {
		h.status.LastError = err.Error()
	} else if state == "running" {
		h.status.LastError = ""
	}
	if state == "starting" || state == "closed" {
		clear(h.components)
	}
	if state == "running" {
		h.aggregateLocked()
	}
	h.mu.Unlock()
	if notify && err != nil {
		select {
		case h.failures <- err:
		default:
		}
	}
}

func (h *healthTracker) setComponent(tag, name, state string, err error, notify bool) {
	h.mu.Lock()
	value := componentHealth{state: state}
	if err != nil {
		value.err = err.Error()
	}
	h.components[name] = value
	h.status.Tag = tag
	h.aggregateLocked()
	h.status.UpdatedAt = time.Now()
	h.mu.Unlock()
	if notify && err != nil {
		select {
		case h.failures <- err:
		default:
		}
	}
}

func (h *healthTracker) aggregateLocked() {
	h.status.State = "running"
	h.status.LastError = ""
	for _, component := range h.components {
		if component.state == "failed" {
			h.status.State = "failed"
			h.status.LastError = component.err
			break
		}
		if component.state == "degraded" {
			h.status.State = "degraded"
			h.status.LastError = component.err
		}
	}
}

func (h *healthTracker) snapshot() HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.status
}

func isRetryableNetworkError(err error) bool {
	if value, ok := err.(net.Error); ok {
		if value.Timeout() {
			return true
		}
	}
	return errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}
