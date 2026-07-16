package inbound

import (
	"context"
	"encoding/binary"
	goerrors "errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	bcnet "github.com/eugene/bypasscore/common/net"
	dnsfeature "github.com/eugene/bypasscore/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type stubDNSClient struct {
	ips    []bcnet.IP
	ttl    uint32
	err    error
	lookup func(string, dnsfeature.IPOption) ([]bcnet.IP, uint32, error)
}

type contextStubDNSClient struct {
	stubDNSClient
	started chan struct{}
}

type rawStubDNSClient struct {
	stubDNSClient
	raw func(context.Context, string, []byte) ([]byte, error)
}

func (c *rawStubDNSClient) LookupIPContext(_ context.Context, domain string, option dnsfeature.IPOption) ([]bcnet.IP, uint32, error) {
	return c.LookupIP(domain, option)
}

func (c *rawStubDNSClient) LookupRawContext(ctx context.Context, domain string, query []byte) ([]byte, error) {
	return c.raw(ctx, domain, query)
}

func (c *contextStubDNSClient) LookupIPContext(ctx context.Context, _ string, _ dnsfeature.IPOption) ([]bcnet.IP, uint32, error) {
	close(c.started)
	<-ctx.Done()
	return nil, 0, ctx.Err()
}

func (c *stubDNSClient) LookupIP(domain string, option dnsfeature.IPOption) ([]bcnet.IP, uint32, error) {
	if c.lookup != nil {
		return c.lookup(domain, option)
	}
	return append([]bcnet.IP(nil), c.ips...), c.ttl, c.err
}

func withEDNS(t *testing.T, raw []byte, payload int, version uint8, dnssecOK bool, copies int) []byte {
	t.Helper()
	msg := unpackDNS(t, raw)
	for range copies {
		var header dnsmessage.ResourceHeader
		if err := header.SetEDNS0(payload, dnsmessage.RCodeSuccess, dnssecOK); err != nil {
			t.Fatal(err)
		}
		header.TTL |= uint32(version) << 16
		msg.Additionals = append(msg.Additionals, dnsmessage.Resource{Header: header, Body: &dnsmessage.OPTResource{}})
	}
	packed, err := msg.AppendPack(nil)
	if err != nil {
		t.Fatal(err)
	}
	return packed
}
func (*stubDNSClient) Type() interface{} { return dnsfeature.ClientType() }
func (*stubDNSClient) Start() error      { return nil }
func (*stubDNSClient) Close() error      { return nil }

func dnsQuery(t testing.TB, id uint16, qtype dnsmessage.Type) []byte {
	t.Helper()
	name, err := dnsmessage.NewName("example.test.")
	if err != nil {
		t.Fatal(err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: name, Type: qtype, Class: dnsmessage.ClassINET,
		}},
	}
	raw, err := msg.AppendPack(nil)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func unpackDNS(t testing.TB, raw []byte) dnsmessage.Message {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		t.Fatalf("unpack DNS response: %v", err)
	}
	return msg
}

func TestDNSListenerAnswersAAndAAAA(t *testing.T) {
	tests := []struct {
		name  string
		qtype dnsmessage.Type
		ip    string
	}{
		{name: "A", qtype: dnsmessage.TypeA, ip: "192.0.2.10"},
		{name: "AAAA", qtype: dnsmessage.TypeAAAA, ip: "2001:db8::10"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listener := NewDNS(&Config{}, &stubDNSClient{ips: []bcnet.IP{net.ParseIP(tc.ip)}, ttl: 42})
			raw, err := listener.handleQuery(dnsQuery(t, 0x1234, tc.qtype), false)
			if err != nil {
				t.Fatal(err)
			}
			response := unpackDNS(t, raw)
			if response.ID != 0x1234 || !response.Response || !response.RecursionAvailable {
				t.Fatalf("unexpected response header: %#v", response.Header)
			}
			if response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) != 1 {
				t.Fatalf("rcode=%v answers=%d", response.RCode, len(response.Answers))
			}
			if response.Answers[0].Header.TTL != 42 {
				t.Fatalf("TTL=%d, want 42", response.Answers[0].Header.TTL)
			}
		})
	}
}

func TestDNSListenerErrorAndNonIPResponses(t *testing.T) {
	nxdomain := NewDNS(&Config{}, &stubDNSClient{err: dnsfeature.RCodeError(dnsmessage.RCodeNameError)})
	raw, err := nxdomain.handleQuery(dnsQuery(t, 7, dnsmessage.TypeA), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := unpackDNS(t, raw).RCode; got != dnsmessage.RCodeNameError {
		t.Fatalf("rcode=%v, want NXDOMAIN", got)
	}

	nonIP := NewDNS(&Config{}, &rawStubDNSClient{raw: func(_ context.Context, domain string, query []byte) ([]byte, error) {
		if domain != "example.test." {
			t.Fatalf("raw query domain=%q", domain)
		}
		response := unpackDNS(t, query)
		response.Response = true
		response.RecursionAvailable = true
		response.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: response.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.TXTResource{TXT: []string{"raw-response"}},
		}}
		return response.AppendPack(nil)
	}})
	raw, err = nonIP.handleQuery(dnsQuery(t, 8, dnsmessage.TypeTXT), false)
	if err != nil {
		t.Fatal(err)
	}
	response := unpackDNS(t, raw)
	if response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) != 1 {
		t.Fatalf("non-IP response: rcode=%v answers=%d", response.RCode, len(response.Answers))
	}

	failure := NewDNS(&Config{}, &stubDNSClient{err: goerrors.New("upstream timeout")})
	raw, err = failure.handleQuery(dnsQuery(t, 9, dnsmessage.TypeA), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := unpackDNS(t, raw).RCode; got != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode=%v, want SERVFAIL", got)
	}
}

func TestValidateRawResponseAcceptsQuestionNameCaseChanges(t *testing.T) {
	request := unpackDNS(t, dnsQuery(t, 91, dnsmessage.TypeTXT))
	mixed, err := dnsmessage.NewName("MiXeD.Example.")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := dnsmessage.NewName("mixed.example.")
	if err != nil {
		t.Fatal(err)
	}
	request.Questions[0].Name = mixed
	response := request
	response.Response = true
	response.Questions = []dnsmessage.Question{{
		Name:  lower,
		Type:  request.Questions[0].Type,
		Class: request.Questions[0].Class,
	}}
	raw, err := response.AppendPack(nil)
	if err != nil {
		t.Fatal(err)
	}
	query, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := dnsfeature.ValidateRawResponse(query, raw); err != nil {
		t.Fatalf("case-only question-name change rejected: %v", err)
	}
}

func TestDNSListenerRejectsUnsafeLimits(t *testing.T) {
	if _, err := positiveLimit(-1, 10, "test"); err == nil {
		t.Fatal("negative limit was accepted")
	}
	if _, err := positiveLimit(maxDNSConfiguredLimit+1, 10, "test"); err == nil {
		t.Fatal("oversized limit was accepted")
	}
	if got, err := positiveLimit(0, 10, "test"); err != nil || got != 10 {
		t.Fatalf("default limit = %d, %v", got, err)
	}
	if _, err := queryByteLimit(511); err == nil {
		t.Fatal("maxQueryBytes below the DNS minimum was accepted")
	}
	if _, err := queryByteLimit(maxDNSMessageSize + 1); err == nil {
		t.Fatal("oversized maxQueryBytes was accepted")
	}
}

func TestDNSListenerEDNSResponse(t *testing.T) {
	listener := NewDNS(&Config{}, &stubDNSClient{ips: []bcnet.IP{net.ParseIP("192.0.2.1")}, ttl: 60})
	query := withEDNS(t, dnsQuery(t, 20, dnsmessage.TypeA), 1232, 0, true, 1)
	raw, err := listener.handleQuery(query, true)
	if err != nil {
		t.Fatal(err)
	}
	response := unpackDNS(t, raw)
	if len(response.Additionals) != 1 || response.Additionals[0].Header.Type != dnsmessage.TypeOPT {
		t.Fatalf("expected one OPT response, got %#v", response.Additionals)
	}
	opt := response.Additionals[0].Header
	if int(opt.Class) != 1232 || opt.DNSSECAllowed() {
		t.Fatalf("unexpected response OPT: payload=%d do=%v", opt.Class, opt.DNSSECAllowed())
	}
}

func TestDNSListenerEDNSBadVersionAndMultipleOPT(t *testing.T) {
	listener := NewDNS(&Config{}, &stubDNSClient{})

	badVersion := withEDNS(t, dnsQuery(t, 21, dnsmessage.TypeA), 1232, 1, false, 1)
	raw, err := listener.handleQuery(badVersion, true)
	if err != nil {
		t.Fatal(err)
	}
	response := unpackDNS(t, raw)
	if len(response.Additionals) != 1 {
		t.Fatalf("BADVERS response has %d additionals", len(response.Additionals))
	}
	if got := response.Additionals[0].Header.ExtendedRCode(response.RCode); got != rcodeBadVersion {
		t.Fatalf("extended rcode=%v, want BADVERS", got)
	}

	multiple := withEDNS(t, dnsQuery(t, 22, dnsmessage.TypeA), 1232, 0, false, 2)
	raw, err = listener.handleQuery(multiple, true)
	if err != nil {
		t.Fatal(err)
	}
	response = unpackDNS(t, raw)
	if response.RCode != dnsmessage.RCodeFormatError || len(response.Additionals) != 0 {
		t.Fatalf("multiple OPT response: rcode=%v additionals=%d", response.RCode, len(response.Additionals))
	}
}

func TestDNSListenerRejectsOversizedAndMalformedQueries(t *testing.T) {
	listener := NewDNS(&Config{}, &stubDNSClient{})
	oversized := make([]byte, defaultDNSMaxQueryBytes+1)
	binary.BigEndian.PutUint16(oversized, 0x3344)
	raw, err := listener.handleQuery(oversized, true)
	if err != nil {
		t.Fatal(err)
	}
	response := unpackDNS(t, raw)
	if response.ID != 0x3344 || response.RCode != dnsmessage.RCodeFormatError {
		t.Fatalf("oversized response: id=%x rcode=%v", response.ID, response.RCode)
	}

	var query dnsmessage.Message
	if err := query.Unpack(dnsQuery(t, 23, dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	query.Questions = append(query.Questions, query.Questions[0])
	packed, err := query.AppendPack(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = listener.handleQuery(packed, true)
	if err != nil {
		t.Fatal(err)
	}
	response = unpackDNS(t, raw)
	if response.RCode != dnsmessage.RCodeFormatError || len(response.Questions) != 0 {
		t.Fatalf("multi-question response: rcode=%v questions=%d", response.RCode, len(response.Questions))
	}
}

func TestDNSListenerUDPTruncation(t *testing.T) {
	ips := make([]bcnet.IP, 80)
	for i := range ips {
		ips[i] = net.IPv4(192, 0, 2, byte(i+1))
	}
	listener := NewDNS(&Config{}, &stubDNSClient{ips: ips, ttl: 60})
	raw, err := listener.handleQuery(dnsQuery(t, 9, dnsmessage.TypeA), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 512 {
		t.Fatalf("UDP response is %d bytes, want <= 512", len(raw))
	}
	response := unpackDNS(t, raw)
	if !response.Truncated || len(response.Answers) != 0 {
		t.Fatalf("expected a truncated response without a partial RR set")
	}
}

func TestDNSListenerServesUDP(t *testing.T) {
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	listener := NewDNS(&Config{Tag: "dns-test", Type: "dns", Listen: "127.0.0.1", Port: port, Network: "udp"},
		&stubDNSClient{ips: []bcnet.IP{net.ParseIP("198.51.100.20")}, ttl: 30})
	if err := listener.Start(); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.Start(); err == nil {
		t.Fatal("starting an active DNS listener twice succeeded")
	}

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(dnsQuery(t, 10, dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := unpackDNS(t, buf[:n]); len(got.Answers) != 1 {
		t.Fatalf("answers=%d, want 1", len(got.Answers))
	}
}

func TestDNSListenerServesIPv6UDP(t *testing.T) {
	probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	listener := NewDNS(&Config{Tag: "dns-v6", Type: "dns", Listen: "::1", Port: port, Network: "udp"},
		&stubDNSClient{ips: []bcnet.IP{net.ParseIP("2001:db8::53")}, ttl: 30})
	if err := listener.Start(); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.ParseIP("::1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(dnsQuery(t, 12, dnsmessage.TypeAAAA)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	response := unpackDNS(t, buf[:n])
	if len(response.Answers) != 1 || response.Answers[0].Header.Type != dnsmessage.TypeAAAA {
		t.Fatalf("unexpected IPv6 response: %#v", response.Answers)
	}
}

func TestDNSListenerRetriesAfterPartialStartFailure(t *testing.T) {
	blocker, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := blocker.LocalAddr().(*net.UDPAddr).Port
	probeTCP, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		_ = blocker.Close()
		t.Skipf("selected UDP port is not available for TCP: %v", err)
	}
	_ = probeTCP.Close()

	listener := NewDNS(&Config{Tag: "dns-retry", Type: "dns", Listen: "127.0.0.1", Port: port, Network: "tcp,udp"}, &stubDNSClient{})
	if err := listener.Start(); err == nil {
		_ = blocker.Close()
		_ = listener.Close()
		t.Fatal("start succeeded while the UDP port was occupied")
	}
	_ = blocker.Close()
	if err := listener.Start(); err != nil {
		t.Fatalf("retry after partial failure: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listener.Start(); err == nil {
		t.Fatal("closed listener was restarted")
	}
}

func TestDNSListenerUDPOverloadReturnsSERVFAIL(t *testing.T) {
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	started := make(chan struct{})
	release := make(chan struct{})
	client := &stubDNSClient{lookup: func(string, dnsfeature.IPOption) ([]bcnet.IP, uint32, error) {
		close(started)
		<-release
		return []bcnet.IP{net.ParseIP("192.0.2.55")}, 60, nil
	}}
	listener := NewDNS(&Config{
		Tag: "dns-overload", Type: "dns", Listen: "127.0.0.1", Port: port,
		Network: "udp", MaxConcurrentQueries: 1,
	}, client)
	if err := listener.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(release)
		_ = listener.Close()
	}()

	first, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Write(dnsQuery(t, 30, dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first DNS lookup did not start")
	}

	second, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := second.Write(dnsQuery(t, 31, dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := second.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	response := unpackDNS(t, buf[:n])
	if response.ID != 31 || response.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("overload response: id=%d rcode=%v", response.ID, response.RCode)
	}
}

func TestDNSListenerCloseCancelsContextLookup(t *testing.T) {
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	client := &contextStubDNSClient{started: make(chan struct{})}
	listener := NewDNS(&Config{Tag: "dns-cancel", Type: "dns", Listen: "127.0.0.1", Port: port, Network: "udp"}, client)
	if err := listener.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(dnsQuery(t, 32, dnsmessage.TypeA)); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	select {
	case <-client.started:
	case <-time.After(2 * time.Second):
		_ = listener.Close()
		t.Fatal("context-aware lookup did not start")
	}

	done := make(chan error, 1)
	go func() { done <- listener.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener close did not cancel the DNS lookup")
	}
}

func TestDNSListenerServesTCP(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	listener := NewDNS(&Config{Tag: "dns-test", Type: "dns", Listen: "127.0.0.1", Port: port, Network: "tcp"},
		&stubDNSClient{ips: []bcnet.IP{net.ParseIP("203.0.113.30")}, ttl: 30})
	if err := listener.Start(); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	for _, id := range []uint16{11, 12} {
		query := dnsQuery(t, id, dnsmessage.TypeA)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(query)))
		if err := writeAll(conn, append(length[:], query...)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatal(err)
		}
		got := unpackDNS(t, response)
		if got.ID != id || len(got.Answers) != 1 {
			t.Fatalf("id=%d answers=%d, want id=%d answers=1", got.ID, len(got.Answers), id)
		}
	}
}

func FuzzDNSListenerHandleQuery(f *testing.F) {
	f.Add(dnsQuery(f, 1, dnsmessage.TypeA), true)
	f.Add([]byte{0x12, 0x34}, false)
	listener := NewDNS(&Config{}, &stubDNSClient{ips: []bcnet.IP{net.ParseIP("192.0.2.1")}, ttl: 60})
	f.Fuzz(func(t *testing.T, raw []byte, udp bool) {
		response, _ := listener.handleQuery(raw, udp)
		limit := maxDNSMessageSize
		if udp {
			limit = maxDNSUDPPayload
		}
		if len(response) > limit {
			t.Fatalf("response length %d exceeds %d", len(response), limit)
		}
	})
}
