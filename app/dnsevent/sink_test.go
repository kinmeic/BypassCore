package dnsevent

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	appdns "github.com/eugene/bypasscore/app/dns"
	bcnet "github.com/eugene/bypasscore/common/net"
)

func TestSinkEmitsUnixDatagram(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sink, err := New(&Config{Socket: path, QueueSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	sink.EmitEvent(NewEvent(appdns.Result{Domain: "example.com", IPs: []bcnet.IP{bcnet.ParseAddress("192.0.2.1").IP()}, TTL: 60, ServerTag: "direct", At: time.Unix(123, 0)}, 3, 7))
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4096)
	n, _, err := listener.ReadFromUnix(buffer)
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(buffer[:n], &event); err != nil {
		t.Fatal(err)
	}
	if event.Sequence != 7 || event.ConfigRevision != 3 || event.ExpiresAt != 183 || event.Domain != "example.com" || len(event.IPs) != 1 || event.IPs[0] != "192.0.2.1" || event.ServerTag != "direct" {
		t.Fatalf("unexpected event: %#v", event)
	}
}

func TestNormalizeConfigBoundsTotalQueueBytes(t *testing.T) {
	if err := Validate(&Config{Socket: "/tmp/events.sock", MaxDatagramBytes: 8192, MaxQueueBytes: 4096}); err == nil {
		t.Fatal("queue byte budget smaller than one datagram was accepted")
	}
	config, err := NormalizeConfig(&Config{Socket: "/tmp/events.sock"})
	if err != nil {
		t.Fatal(err)
	}
	if config.QueueSize != 256 || config.MaxQueueBytes != 1<<20 {
		t.Fatalf("unexpected defaults: %#v", config)
	}
}
