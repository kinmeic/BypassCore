package dns

import (
	"context"
	"errors"
	"net"
	"net/url"
	"testing"

	bcnet "github.com/eugene/bypasscore/common/net"
	dnsfeature "github.com/eugene/bypasscore/features/dns"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
)

func validDNSExchange(t *testing.T) (*dnsRequest, []byte) {
	t.Helper()
	reqs, err := buildReqMsgs("example.com.", dnsfeature.IPOption{IPv4Enable: true}, func() uint16 { return 42 }, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := reqs[0]
	response := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 42, Response: true, RecursionAvailable: true},
		Questions: append([]dnsmessage.Question(nil), req.msg.Questions...),
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: req.msg.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
		}},
	}
	payload, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return req, payload
}

func TestParseResponseForRequestValidatesAssociation(t *testing.T) {
	req, payload := validDNSExchange(t)
	record, err := parseResponseForRequest(payload, req)
	if err != nil || len(record.IP) != 1 {
		t.Fatalf("valid response rejected: record=%v err=%v", record, err)
	}

	badID := append([]byte(nil), payload...)
	badID[1]++
	if _, err := parseResponseForRequest(badID, req); err == nil {
		t.Fatal("mismatched transaction ID accepted")
	}

	notResponse := append([]byte(nil), payload...)
	notResponse[2] &^= 0x80
	if _, err := parseResponseForRequest(notResponse, req); err == nil {
		t.Fatal("query packet accepted as response")
	}

	wrongReq := *req
	wrongMsg := *req.msg
	wrongMsg.Questions = append([]dnsmessage.Question(nil), req.msg.Questions...)
	wrongMsg.Questions[0].Type = dnsmessage.TypeAAAA
	wrongReq.msg = &wrongMsg
	if _, err := parseResponseForRequest(payload, &wrongReq); err == nil {
		t.Fatal("mismatched question accepted")
	}
}

type dialTrackingServer struct{ calls int }

func (*dialTrackingServer) Name() string         { return "tracking" }
func (*dialTrackingServer) IsDisableCache() bool { return true }
func (*dialTrackingServer) QueryIP(context.Context, string, dnsfeature.IPOption) ([]bcnet.IP, uint32, error) {
	return nil, 0, nil
}
func (s *dialTrackingServer) SetDialer(Dialer) { s.calls++ }

func TestDNSSetDialerSkipsLocalServers(t *testing.T) {
	remote, local := new(dialTrackingServer), new(dialTrackingServer)
	server := &DNS{clients: []*Client{{server: remote}, {server: local, localDirect: true}}}
	server.SetDialer(func(context.Context, bcnet.Destination) (net.Conn, error) {
		return nil, errors.New("unused")
	})
	if remote.calls != 1 || local.calls != 0 {
		t.Fatalf("dialer calls remote=%d local=%d", remote.calls, local.calls)
	}
}

func TestDoHH2CUsesCleartextHTTP2(t *testing.T) {
	u, _ := url.Parse("h2c://127.0.0.1:8053/dns-query")
	server := NewDoHNameServer(u, true, false, false, 0, nil)
	defer server.Close()
	if server.dohURL != "http://127.0.0.1:8053/dns-query" {
		t.Fatalf("unexpected h2c URL %q", server.dohURL)
	}
	if _, ok := server.httpClient.Transport.(*http2.Transport); !ok {
		t.Fatalf("h2c transport is %T", server.httpClient.Transport)
	}
}

func TestUDPLocalURLParsesDestination(t *testing.T) {
	server, err := NewServer(bcnet.UDPDestination(bcnet.DomainAddress("udp+local://1.1.1.1:5353"), 0), false, false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	classic := server.(*ClassicNameServer)
	if classic.address.NetAddr() != "1.1.1.1:5353" {
		t.Fatalf("destination = %s", classic.address.NetAddr())
	}
}
