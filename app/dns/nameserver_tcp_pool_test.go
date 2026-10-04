package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func tcpRawQuery(t *testing.T, id uint16) []byte {
	t.Helper()
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("pool.example."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}},
	}
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func serveTCPDNSPipe(conn net.Conn, maxResponses int) {
	defer conn.Close()
	for responses := 0; maxResponses == 0 || responses < maxResponses; responses++ {
		var length uint16
		if binary.Read(conn, binary.BigEndian, &length) != nil {
			return
		}
		query := make([]byte, int(length))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		query[2] |= 0x80
		query[3] |= 0x80
		if binary.Write(conn, binary.BigEndian, uint16(len(query))) != nil || writeDNSPayload(conn, query) != nil {
			return
		}
	}
}

func pooledTCPServer(t *testing.T, dial func(context.Context) (net.Conn, error)) *TCPNameServer {
	t.Helper()
	u, _ := url.Parse("tcp://127.0.0.1:53")
	server, err := NewTCPNameServer(u, true, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.dial = dial
	return server
}

func TestTCPNameServerReusesValidatedConnection(t *testing.T) {
	var dials atomic.Int32
	server := pooledTCPServer(t, func(context.Context) (net.Conn, error) {
		dials.Add(1)
		client, peer := net.Pipe()
		go serveTCPDNSPipe(peer, 0)
		return client, nil
	})
	defer server.Close()
	for id := uint16(1); id <= 2; id++ {
		if _, err := server.QueryRaw(context.Background(), tcpRawQuery(t, id)); err != nil {
			t.Fatal(err)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("TCP dials=%d, want 1", got)
	}
}

func TestTCPNameServerRetriesStalePooledConnectionOnce(t *testing.T) {
	var dials atomic.Int32
	server := pooledTCPServer(t, func(context.Context) (net.Conn, error) {
		count := dials.Add(1)
		client, peer := net.Pipe()
		max := 0
		if count == 1 {
			max = 1
		}
		go serveTCPDNSPipe(peer, max)
		return client, nil
	})
	defer server.Close()
	if _, err := server.QueryRaw(context.Background(), tcpRawQuery(t, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.QueryRaw(context.Background(), tcpRawQuery(t, 2)); err != nil {
		t.Fatal(err)
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("TCP dials=%d, want stale retry to dial twice", got)
	}
}

func TestTCPNameServerCloseInterruptsActiveExchange(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	server := pooledTCPServer(t, func(context.Context) (net.Conn, error) { return client, nil })
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		_, err := server.QueryRaw(t.Context(), tcpRawQuery(t, 1))
		done <- err
	}()
	var size uint16
	if err := binary.Read(peer, binary.BigEndian, &size); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, make([]byte, int(size))); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("exchange succeeded after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt active I/O")
	}
	if len(server.idleConns) != 0 {
		t.Fatal("closed pool retained a connection")
	}
}

func TestTCPNameServerCancelInterruptsActiveExchange(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	server := pooledTCPServer(t, func(context.Context) (net.Conn, error) { return client, nil })
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := server.QueryRaw(ctx, tcpRawQuery(t, 1)); done <- err }()
	var size uint16
	if err := binary.Read(peer, binary.BigEndian, &size); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, make([]byte, int(size))); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("exchange succeeded after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("exchange did not observe cancellation")
	}
	if len(server.idleConns) != 0 {
		t.Fatal("canceled connection returned to pool")
	}
}
