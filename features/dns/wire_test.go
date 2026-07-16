package dns

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func testWireExchange(t testing.TB) ([]byte, []byte) {
	t.Helper()
	name := dnsmessage.MustNewName("Example.COM.")
	question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}
	queryMessage := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{question},
	}
	query, err := queryMessage.Pack()
	if err != nil {
		t.Fatal(err)
	}
	question.Name = dnsmessage.MustNewName("example.com.")
	responseMessage := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234, Response: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.TXTResource{TXT: []string{"ok"}},
		}},
	}
	response, err := responseMessage.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return query, response
}

func TestValidateRawResponse(t *testing.T) {
	query, response := testWireExchange(t)
	if err := ValidateRawResponse(query, response); err != nil {
		t.Fatalf("valid exchange rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "wrong ID", mutate: func(b []byte) { b[1]++ }},
		{name: "not response", mutate: func(b []byte) { b[2] &^= 0x80 }},
		{name: "wrong opcode", mutate: func(b []byte) { b[2] ^= 0x08 }},
		{name: "wrong question type", mutate: func(b []byte) { b[len(query)-4] = 0; b[len(query)-3] = byte(dnsmessage.TypeMX) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bad := append([]byte(nil), response...)
			tc.mutate(bad)
			if err := ValidateRawResponse(query, bad); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}

	if err := ValidateRawResponse(query, response[:len(response)-1]); err == nil {
		t.Fatal("truncated response accepted")
	}
}

func FuzzValidateRawResponse(f *testing.F) {
	query, response := testWireExchange(f)
	f.Add(query, response)
	f.Add([]byte{0, 1}, []byte{2, 3})
	f.Fuzz(func(t *testing.T, query, response []byte) {
		_ = ValidateRawResponse(query, response)
	})
}
