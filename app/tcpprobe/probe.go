// Package tcpprobe measures a TCP handshake without sending application data.
package tcpprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultTimeout = 3 * time.Second
	MaxTimeout     = 10 * time.Second
)

var ErrInvalidRequest = errors.New("invalid TCP probe request")

type Result struct {
	Host          string  `json:"host"`
	Port          int     `json:"port"`
	RemoteAddress string  `json:"remoteAddress"`
	LatencyMs     float64 `json:"latencyMs"`
}

// Connect completes one TCP handshake and closes the connection immediately.
// The context and timeout bound DNS resolution and connection establishment.
func Connect(ctx context.Context, host string, port int, timeout time.Duration) (Result, error) {
	host = strings.TrimSpace(host)
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return Result{}, fmt.Errorf("%w: host is required", ErrInvalidRequest)
	}
	if len(host) > 255 {
		return Result{}, fmt.Errorf("%w: host is too long", ErrInvalidRequest)
	}
	if strings.ContainsAny(host, "\x00\r\n") {
		return Result{}, fmt.Errorf("%w: host contains control characters", ErrInvalidRequest)
	}
	if port < 1 || port > 65535 {
		return Result{}, fmt.Errorf("%w: port must be between 1 and 65535", ErrInvalidRequest)
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < time.Millisecond || timeout > MaxTimeout {
		return Result{}, fmt.Errorf("%w: timeout must be between 1ms and %s", ErrInvalidRequest, MaxTimeout)
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var addresses []net.IPAddr
	if parsed := net.ParseIP(host); parsed != nil {
		addresses = []net.IPAddr{{IP: parsed}}
	} else {
		var err error
		addresses, err = net.DefaultResolver.LookupIPAddr(probeCtx, host)
		if err != nil {
			return Result{}, fmt.Errorf("resolve %s: %w", host, err)
		}
		if len(addresses) == 0 {
			return Result{}, fmt.Errorf("resolve %s: no addresses", host)
		}
	}

	dialer := &net.Dialer{KeepAlive: -1}
	var lastErr error
	for _, address := range addresses {
		start := time.Now()
		connection, err := dialer.DialContext(
			probeCtx,
			"tcp",
			net.JoinHostPort(address.String(), strconv.Itoa(port)),
		)
		if err != nil {
			lastErr = err
			continue
		}
		latency := time.Since(start)
		remoteAddress := connection.RemoteAddr().String()
		_ = connection.Close()
		return Result{
			Host:          host,
			Port:          port,
			RemoteAddress: remoteAddress,
			LatencyMs:     float64(latency.Microseconds()) / 1000,
		}, nil
	}
	return Result{}, fmt.Errorf("connect to %s:%d: %w", host, port, lastErr)
}
