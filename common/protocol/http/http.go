// Package http implements HTTP Host header sniffing. Given the first bytes of
// a TCP connection, it parses the HTTP request to extract the Host header,
// enabling domain-based routing for transparent proxy flows.
package http

import (
	"bytes"
	"strings"
)

// SniffHost parses an HTTP request from the given bytes and returns the Host
// header value (without port), or "" if the bytes are not an HTTP request or
// no Host header is present.
func SniffHost(data []byte) string {
	// Quick check: HTTP methods
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "PATCH "}
	isHTTP := false
	for _, m := range methods {
		if len(data) >= len(m) && string(data[:len(m)]) == m {
			isHTTP = true
			break
		}
	}
	if !isHTTP {
		return ""
	}

	// Find the end of headers (CRLF CRLF) or just the first line + Host line
	// within the first buffer. We only need the Host header.
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimRight(line, "\r")
		// Case-insensitive "Host:" prefix
		if len(line) > 5 {
			prefix := strings.ToLower(string(line[:5]))
			if prefix == "host:" {
				host := strings.TrimSpace(string(line[5:]))
				// Strip port if present
				if idx := strings.LastIndex(host, ":"); idx > 0 {
					// Check if it's an IPv6 address (contains multiple colons)
					if strings.Count(host, ":") > 1 {
						// IPv6: [::1]:8080 or ::1
						if host[0] == '[' {
							if idx := strings.Index(host, "]"); idx > 0 {
								return host[1:idx]
							}
						}
					} else {
						host = host[:idx]
					}
				}
				return host
			}
		}
	}
	return ""
}
