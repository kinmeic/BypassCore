package dns

import (
	"strings"

	"github.com/eugene/bypasscore/common/errors"
	"golang.org/x/net/dns/dnsmessage"
)

const maxWireMessageSize = 65535

// ValidateRawResponse verifies that response is a structurally valid DNS
// response associated with query. Raw DNS transports must call this before a
// response is accepted, cached, or returned to an inbound. Keeping the check at
// the feature boundary also allows a multi-upstream client to fall back after a
// poisoned, stale, or otherwise unrelated response.
func ValidateRawResponse(query, response []byte) error {
	if len(query) < 12 || len(query) > maxWireMessageSize {
		return errors.New("invalid raw DNS query length")
	}
	if len(response) < 12 || len(response) > maxWireMessageSize {
		return errors.New("invalid raw DNS response length")
	}

	queryHeader, queryQuestions, err := parseWireQuestions(query)
	if err != nil {
		return errors.New("invalid raw DNS query").Base(err)
	}
	if queryHeader.Response {
		return errors.New("raw DNS query has the response bit set")
	}
	if len(queryQuestions) == 0 {
		return errors.New("raw DNS query has no question")
	}

	responseHeader, responseQuestions, err := parseWireQuestions(response)
	if err != nil {
		return errors.New("invalid raw DNS response").Base(err)
	}
	if !responseHeader.Response || responseHeader.ID != queryHeader.ID || responseHeader.OpCode != queryHeader.OpCode {
		return errors.New("raw DNS response does not match query header")
	}
	if len(responseQuestions) != len(queryQuestions) {
		return errors.New("raw DNS response does not match query questions")
	}
	for i := range queryQuestions {
		if !strings.EqualFold(responseQuestions[i].Name.String(), queryQuestions[i].Name.String()) ||
			responseQuestions[i].Type != queryQuestions[i].Type ||
			responseQuestions[i].Class != queryQuestions[i].Class {
			return errors.New("raw DNS response does not match query question")
		}
	}
	return nil
}

func parseWireQuestions(message []byte) (dnsmessage.Header, []dnsmessage.Question, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(message)
	if err != nil {
		return dnsmessage.Header{}, nil, err
	}
	questions, err := parser.AllQuestions()
	if err != nil {
		return dnsmessage.Header{}, nil, err
	}
	// Walk every section to reject truncated records and invalid compression
	// pointers without decoding record bodies. This preserves support for raw
	// record types that dnsmessage does not model explicitly.
	if err := parser.SkipAllAnswers(); err != nil {
		return dnsmessage.Header{}, nil, err
	}
	if err := parser.SkipAllAuthorities(); err != nil {
		return dnsmessage.Header{}, nil, err
	}
	if err := parser.SkipAllAdditionals(); err != nil {
		return dnsmessage.Header{}, nil, err
	}
	return header, questions, nil
}
