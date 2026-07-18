package tcpprobe

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestConnectMeasuresHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
		}
		close(accepted)
	}()

	address := listener.Addr().(*net.TCPAddr)
	result, err := Connect(context.Background(), "127.0.0.1", address.Port, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.Host != "127.0.0.1" || result.Port != address.Port || result.RemoteAddress == "" || result.LatencyMs < 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("server did not accept probe")
	}
}

func TestConnectValidatesRequest(t *testing.T) {
	for _, test := range []struct {
		host    string
		port    int
		timeout time.Duration
	}{
		{"", 443, time.Second},
		{"example.com", 0, time.Second},
		{"example.com", 65536, time.Second},
		{"example.com", 443, MaxTimeout + time.Millisecond},
	} {
		if _, err := Connect(context.Background(), test.host, test.port, test.timeout); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("Connect(%q, %d, %s) error=%v", test.host, test.port, test.timeout, err)
		}
	}
}

func TestConnectHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Connect(ctx, "192.0.2.1", 443, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
}
