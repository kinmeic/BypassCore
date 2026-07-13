package http

import (
	"testing"
)

// TestSniffHost_Basic verifies the most common case: GET + Host header.
func TestSniffHost_Basic(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if got := SniffHost(data); got != "example.com" {
		t.Errorf("SniffHost = %q, want example.com", got)
	}
}

// TestSniffHost_PortStripped verifies port stripping from the Host header.
func TestSniffHost_PortStripped(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n")
	if got := SniffHost(data); got != "example.com" {
		t.Errorf("SniffHost = %q, want example.com (port stripped)", got)
	}
}

// TestSniffHost_AllMethods verifies all HTTP methods are recognized.
func TestSniffHost_AllMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH"}
	for _, m := range methods {
		data := []byte(m + " / HTTP/1.1\r\nHost: " + m + ".test\r\n\r\n")
		if got := SniffHost(data); got != m+".test" {
			t.Errorf("SniffHost(%s) = %q, want %s.test", m, got, m)
		}
	}
}

// TestSniffHost_NoHost returns "" when there's no Host header.
func TestSniffHost_NoHost(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n")
	if got := SniffHost(data); got != "" {
		t.Errorf("SniffHost = %q, want empty (no Host)", got)
	}
}

// TestSniffHost_CaseInsensitive verifies "host:" (lowercase) is recognized.
func TestSniffHost_CaseInsensitive(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nhost: lower.com\r\n\r\n")
	if got := SniffHost(data); got != "lower.com" {
		t.Errorf("SniffHost = %q, want lower.com", got)
	}
}

// TestSniffHost_IPV6Bracketed verifies [::1]:8080 → ::1.
func TestSniffHost_IPV6Bracketed(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n")
	if got := SniffHost(data); got != "::1" {
		t.Errorf("SniffHost = %q, want ::1", got)
	}
}

// TestSniffHost_NotHTTP returns "" for non-HTTP data (e.g. TLS).
func TestSniffHost_NotHTTP(t *testing.T) {
	data := []byte{0x16, 0x03, 0x01, 0x00, 0x00}
	if got := SniffHost(data); got != "" {
		t.Errorf("SniffHost(TLS) = %q, want empty", got)
	}
}

// TestSniffHost_EmptyInput returns "".
func TestSniffHost_EmptyInput(t *testing.T) {
	if got := SniffHost(nil); got != "" {
		t.Errorf("SniffHost(nil) = %q, want empty", got)
	}
	if got := SniffHost([]byte{}); got != "" {
		t.Errorf("SniffHost([]) = %q, want empty", got)
	}
}

// TestSniffHost_TrailingWhitespace verifies whitespace trimming around the
// Host value.
func TestSniffHost_TrailingWhitespace(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost:   spaced.com  \r\n\r\n")
	if got := SniffHost(data); got != "spaced.com" {
		t.Errorf("SniffHost = %q, want spaced.com", got)
	}
}
