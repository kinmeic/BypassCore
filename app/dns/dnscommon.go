package dns

import (
	"encoding/binary"
	"math"
	"strings"
	"time"

	"github.com/eugene/bypasscore/common"
	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/common/net"
	dns_feature "github.com/eugene/bypasscore/features/dns"

	"golang.org/x/net/dns/dnsmessage"
)

// Fqdn normalizes domain to make sure it ends with '.'.
func Fqdn(domain string) string {
	if len(domain) > 0 && strings.HasSuffix(domain, ".") {
		return domain
	}
	return domain + "."
}

type record struct {
	A    *IPRecord
	AAAA *IPRecord
}

// IPRecord is a cacheable item for a resolved domain.
type IPRecord struct {
	ReqID     uint16
	IP        []net.IP
	Expire    time.Time
	RCode     dnsmessage.RCode
	RawHeader *dnsmessage.Header
}

func (r *IPRecord) getIPs() ([]net.IP, int32, error) {
	if r == nil {
		return nil, 0, errRecordNotFound
	}

	untilExpire := time.Until(r.Expire).Seconds()
	ttl := int32(math.Ceil(untilExpire))

	if r.RCode != dnsmessage.RCodeSuccess {
		return nil, ttl, dns_feature.RCodeError(r.RCode)
	}
	if len(r.IP) == 0 {
		return nil, ttl, dns_feature.ErrEmptyResponse
	}

	return r.IP, ttl, nil
}

var errRecordNotFound = errors.New("record not found")

type dnsRequest struct {
	reqType dnsmessage.Type
	domain  string
	start   time.Time
	msg     *dnsmessage.Message
}

func genEDNS0Options(clientIP net.IP, padding int) *dnsmessage.Resource {
	if len(clientIP) == 0 && padding == 0 {
		return nil
	}

	const EDNS0SUBNET = 0x8
	const EDNS0PADDING = 0xc

	opt := new(dnsmessage.Resource)
	common.Must(opt.Header.SetEDNS0(1350, 0xfe00, true))
	body := dnsmessage.OPTResource{}
	opt.Body = &body

	if len(clientIP) != 0 {
		var netmask int
		var family uint16

		if len(clientIP) == 4 {
			family = 1
			netmask = 24 // 24 for IPV4, 96 for IPv6
		} else {
			family = 2
			netmask = 96
		}

		b := make([]byte, 4)
		binary.BigEndian.PutUint16(b[0:], family)
		b[2] = byte(netmask)
		b[3] = 0
		switch family {
		case 1:
			ip := clientIP.To4().Mask(net.CIDRMask(netmask, net.IPv4len*8))
			needLength := (netmask + 8 - 1) / 8 // division rounding up
			b = append(b, ip[:needLength]...)
		case 2:
			ip := clientIP.Mask(net.CIDRMask(netmask, net.IPv6len*8))
			needLength := (netmask + 8 - 1) / 8 // division rounding up
			b = append(b, ip[:needLength]...)
		}

		body.Options = append(body.Options,
			dnsmessage.Option{
				Code: EDNS0SUBNET,
				Data: b,
			})
	}

	if padding != 0 {
		body.Options = append(body.Options,
			dnsmessage.Option{
				Code: EDNS0PADDING,
				Data: make([]byte, padding),
			})
	}

	return opt
}

func buildReqMsgs(domain string, option dns_feature.IPOption, reqIDGen func() uint16, reqOpts *dnsmessage.Resource) ([]*dnsRequest, error) {
	name, err := dnsmessage.NewName(domain)
	if err != nil {
		return nil, err
	}

	qA := dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}

	qAAAA := dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypeAAAA,
		Class: dnsmessage.ClassINET,
	}

	var reqs []*dnsRequest
	now := time.Now()

	if option.IPv4Enable {
		msg := new(dnsmessage.Message)
		msg.Header.ID = reqIDGen()
		msg.Header.RecursionDesired = true
		msg.Questions = []dnsmessage.Question{qA}
		if reqOpts != nil {
			msg.Additionals = append(msg.Additionals, *reqOpts)
		}
		reqs = append(reqs, &dnsRequest{
			reqType: dnsmessage.TypeA,
			domain:  domain,
			start:   now,
			msg:     msg,
		})
	}

	if option.IPv6Enable {
		msg := new(dnsmessage.Message)
		msg.Header.ID = reqIDGen()
		msg.Header.RecursionDesired = true
		msg.Questions = []dnsmessage.Question{qAAAA}
		if reqOpts != nil {
			msg.Additionals = append(msg.Additionals, *reqOpts)
		}
		reqs = append(reqs, &dnsRequest{
			reqType: dnsmessage.TypeAAAA,
			domain:  domain,
			start:   now,
			msg:     msg,
		})
	}

	return reqs, nil
}

// parseResponseForRequest rejects unsolicited, stale, or malformed DNS
// responses before they can enter the cache.
func parseResponseForRequest(payload []byte, req *dnsRequest) (*IPRecord, error) {
	if req == nil || req.msg == nil || len(req.msg.Questions) != 1 {
		return nil, errors.New("invalid DNS request metadata")
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(payload)
	if err != nil {
		return nil, errors.New("failed to parse DNS response header").Base(err)
	}
	if !header.Response {
		return nil, errors.New("DNS message is not a response")
	}
	if header.ID != req.msg.ID {
		return nil, errors.New("DNS response ID mismatch")
	}
	if header.OpCode != req.msg.OpCode {
		return nil, errors.New("DNS response opcode mismatch")
	}
	question, err := parser.Question()
	if err != nil {
		return nil, errors.New("DNS response has no matching question").Base(err)
	}
	expected := req.msg.Questions[0]
	if !strings.EqualFold(question.Name.String(), expected.Name.String()) ||
		question.Type != expected.Type || question.Class != expected.Class {
		return nil, errors.New("DNS response question mismatch")
	}
	if _, err := parser.Question(); err != dnsmessage.ErrSectionDone {
		return nil, errors.New("DNS response contains unexpected questions")
	}
	// Decode all sections so malformed authority/additional records cannot be
	// accepted into the cache. Only addresses for the requested owner (or its
	// CNAME target), type and class belong to this lookup.
	var message dnsmessage.Message
	if err := message.Unpack(payload); err != nil {
		return nil, errors.New("invalid DNS response").Base(err)
	}
	record := &IPRecord{ReqID: header.ID, RCode: header.RCode, RawHeader: &header}
	ttl := uint32(dns_feature.DefaultTTL)
	hasTTL := false
	includeTTL := func(value uint32) {
		if value == 0 {
			value = 1
		}
		// The public cache API represents TTL as int32.
		if value > math.MaxInt32 {
			value = math.MaxInt32
		}
		if !hasTTL || value < ttl {
			ttl = value
		}
		hasTTL = true
	}
	aliases := make(map[string]dnsmessage.Resource)
	for _, answer := range message.Answers {
		if answer.Header.Class != expected.Class || answer.Header.Type != dnsmessage.TypeCNAME {
			continue
		}
		owner := strings.ToLower(answer.Header.Name.String())
		if previous, exists := aliases[owner]; exists && !strings.EqualFold(
			previous.Body.(*dnsmessage.CNAMEResource).CNAME.String(), answer.Body.(*dnsmessage.CNAMEResource).CNAME.String()) {
			return nil, errors.New("conflicting DNS CNAME targets")
		}
		aliases[owner] = answer
	}
	owner := strings.ToLower(expected.Name.String())
	visited := make(map[string]bool)
	for {
		if visited[owner] {
			return nil, errors.New("DNS CNAME loop")
		}
		visited[owner] = true
		alias, exists := aliases[owner]
		if !exists {
			break
		}
		includeTTL(alias.Header.TTL)
		owner = strings.ToLower(alias.Body.(*dnsmessage.CNAMEResource).CNAME.String())
	}
	for _, answer := range message.Answers {
		if answer.Header.Class != expected.Class || answer.Header.Type != expected.Type ||
			!strings.EqualFold(answer.Header.Name.String(), owner) {
			continue
		}
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			record.IP = append(record.IP, net.IPAddress(body.A[:]).IP())
		case *dnsmessage.AAAAResource:
			record.IP = append(record.IP, net.IPAddress(body.AAAA[:]).IP())
		default:
			continue
		}
		includeTTL(answer.Header.TTL)
	}
	record.Expire = time.Now().Add(time.Duration(ttl) * time.Second)
	return record, nil
}
