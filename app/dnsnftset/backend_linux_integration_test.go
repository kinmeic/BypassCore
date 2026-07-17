//go:build linux

package dnsnftset

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	appdns "github.com/eugene/bypasscore/app/dns"
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/google/nftables"
)

func TestNFTElementsEncodePlainIntervalEndpoints(t *testing.T) {
	set := &nftables.Set{Interval: true}
	key := net.ParseIP("192.0.2.1").To4()
	timeout := 30 * time.Second
	elements := nftElements(set, update{key: key, timeout: timeout})
	if len(elements) != 2 {
		t.Fatalf("elements=%d, want 2", len(elements))
	}
	if !bytes.Equal(elements[0].Key, key) || elements[0].IntervalEnd || elements[0].Timeout != timeout {
		t.Fatalf("unexpected interval start: %#v", elements[0])
	}
	if !bytes.Equal(elements[1].Key, nextAddress(key)) || !elements[1].IntervalEnd || elements[1].Timeout != timeout {
		t.Fatalf("unexpected interval end: %#v", elements[1])
	}
}

func TestKernelNFTSetWriter(t *testing.T) {
	if os.Getenv("BYPASSCORE_NFTSET_INTEGRATION") != "1" {
		t.Skip("set BYPASSCORE_NFTSET_INTEGRATION=1 and run as root")
	}
	tableName := fmt.Sprintf("bc_dns_%d", os.Getpid())
	table := &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}
	create := &nftables.Conn{}
	create.AddTable(table)
	v4 := &nftables.Set{Table: table, Name: "result4", KeyType: nftables.TypeIPAddr, Interval: true, HasTimeout: true}
	v6 := &nftables.Set{Table: table, Name: "result6", KeyType: nftables.TypeIP6Addr, Interval: true, HasTimeout: true}
	existing := net.ParseIP("192.0.2.1").To4()
	if err := create.AddSet(v4, nftElements(v4, update{key: existing})); err != nil {
		t.Fatal(err)
	}
	if err := create.AddSet(v6, nil); err != nil {
		t.Fatal(err)
	}
	if err := create.Flush(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup := &nftables.Conn{}
		cleanup.DelTable(table)
		_ = cleanup.Flush()
	})

	writer, err := New(&Config{
		BatchSize: 16, FlushIntervalMs: 5,
		Policies: []Policy{{
			ServerTags: []string{"direct"},
			IPv4Set:    "inet@" + tableName + "@result4",
			IPv6Set:    "inet@" + tableName + "@result6",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Probe(); err != nil {
		t.Fatal(err)
	}
	writer.Emit(appdns.Result{
		ServerTag: "direct", TTL: 60,
		IPs: []bcnet.IP{
			bcnet.IP(net.ParseIP("192.0.2.1").To4()), // already exists: exercises per-element retry
			bcnet.IP(net.ParseIP("192.0.2.2").To4()),
			bcnet.IP(net.ParseIP("2001:db8::1").To16()),
		},
	})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		lookup := &nftables.Conn{}
		set4, err4 := lookup.GetSetByName(table, "result4")
		set6, err6 := lookup.GetSetByName(table, "result6")
		if err4 == nil && err6 == nil {
			elements4, read4 := lookup.GetSetElements(set4)
			elements6, read6 := lookup.GetSetElements(set6)
			if read4 == nil && read6 == nil && hasIP(elements4, "192.0.2.1") && hasIP(elements4, "192.0.2.2") && hasIP(elements6, "2001:db8::1") {
				status := writer.Status()
				if !status.Ready || status.Added != 2 || status.Existing != 1 {
					t.Fatalf("writer became unhealthy: %#v", writer.Status())
				}
				if !hasExpiringIP(elements4, "192.0.2.2") || !hasExpiringIP(elements6, "2001:db8::1") {
					t.Fatal("new elements were not installed with a timeout")
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for kernel elements; status=%#v", writer.Status())
}

func hasExpiringIP(elements []nftables.SetElement, want string) bool {
	for _, element := range elements {
		if net.IP(element.Key).String() == want {
			return element.Expires > 0 && element.Expires <= 60*time.Second
		}
	}
	return false
}

func hasIP(elements []nftables.SetElement, want string) bool {
	for _, element := range elements {
		if net.IP(element.Key).String() == want {
			return true
		}
	}
	return false
}
