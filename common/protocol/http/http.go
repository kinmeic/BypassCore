// Package http implements bounded HTTP/1 request metadata sniffing.
package http

import (
	"bytes"
	"net"
	"strconv"
	"strings"
)

var methods = []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH"}

// SniffHost returns the normalized Host header without its port.
func SniffHost(data []byte) string {
	host, _ := SniffRequest(data)
	return host
}

// SniffRequest extracts Host plus lowercase HTTP headers and request-line
// attributes. Callers should provide a complete header block so segmented
// attributes cannot bypass routing conditions.
func SniffRequest(data []byte) (string, map[string]string) {
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return "", nil
	}
	lines := bytes.Split(data[:headerEnd], []byte("\r\n"))
	if len(lines) == 0 {
		return "", nil
	}
	request := strings.Fields(string(lines[0]))
	if len(request) != 3 || !knownMethod(request[0]) || !strings.HasPrefix(request[2], "HTTP/1.") {
		return "", nil
	}
	attributes := map[string]string{":method": request[0], ":path": request[1]}
	host := ""
	for _, line := range lines[1:] {
		parts := bytes.SplitN(line, []byte{':'}, 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(string(parts[0])))
		value := strings.TrimSpace(string(parts[1]))
		if key == "" || strings.ContainsAny(key, " \t\r\n") || strings.ContainsAny(value, "\r\n\x00") {
			return "", nil
		}
		attributes[key] = value
		if key == "host" {
			host = normalizeHost(value)
			if host == "" {
				return "", nil
			}
		}
	}
	return host, attributes
}

func knownMethod(method string) bool {
	for _, candidate := range methods {
		if strings.EqualFold(method, candidate) {
			return true
		}
	}
	return false
}

func normalizeHost(value string) string {
	if host, portText, err := net.SplitHostPort(value); err == nil {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return ""
		}
		return strings.Trim(host, "[]")
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.Trim(value, "[]")
	}
	if value == "" || strings.ContainsAny(value, " \t/\\") {
		return ""
	}
	// An unbracketed IPv6 literal has multiple colons and no port.
	if strings.Count(value, ":") == 1 {
		return "" // malformed host:port
	}
	return value
}
