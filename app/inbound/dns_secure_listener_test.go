package inbound

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	bcnet "github.com/eugene/bypasscore/common/net"
	"golang.org/x/net/dns/dnsmessage"
)

func testDoHListener() *DNSListener {
	return &DNSListener{
		cfg:            &Config{Tag: "doh-test"},
		client:         &stubDNSClient{ips: []bcnet.IP{{192, 0, 2, 1}}, ttl: 60},
		ctx:            context.Background(),
		querySlots:     make(chan struct{}, 2),
		queryBytes:     4096,
		allowedClients: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}
}

func TestDoHHandlerPOSTAndGET(t *testing.T) {
	listener := testDoHListener()
	query := dnsQuery(t, 81, dnsmessage.TypeA)
	tests := []*http.Request{
		httptest.NewRequest(http.MethodPost, "https://dns.example/dns-query", bytes.NewReader(query)),
		httptest.NewRequest(http.MethodGet, "https://dns.example/dns-query?dns="+base64.RawURLEncoding.EncodeToString(query), nil),
	}
	tests[0].Header.Set("Content-Type", "application/dns-message")
	for _, request := range tests {
		request.RemoteAddr = "192.0.2.9:12345"
		recorder := httptest.NewRecorder()
		listener.handleDoH(recorder, request)
		if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/dns-message" {
			t.Fatalf("DoH status=%d content-type=%q body=%q", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
		}
		if got := unpackDNS(t, recorder.Body.Bytes()); got.ID != 81 || len(got.Answers) != 1 {
			t.Fatalf("DoH response id=%d answers=%d", got.ID, len(got.Answers))
		}
	}
}

func TestDoHHandlerAccessAndMediaType(t *testing.T) {
	listener := testDoHListener()
	request := httptest.NewRequest(http.MethodPost, "https://dns.example/dns-query", bytes.NewReader(dnsQuery(t, 1, dnsmessage.TypeA)))
	request.RemoteAddr = "198.51.100.1:1234"
	recorder := httptest.NewRecorder()
	listener.handleDoH(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unauthorized DoH status=%d", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "https://dns.example/dns-query", bytes.NewReader(dnsQuery(t, 1, dnsmessage.TypeA)))
	request.RemoteAddr = "192.0.2.1:1234"
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	listener.handleDoH(recorder, request)
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("bad media type status=%d", recorder.Code)
	}
}

func TestSecureDNSListenerRequiresCertificate(t *testing.T) {
	for _, listenerType := range []string{"dot", "doh"} {
		listener := NewDNS(&Config{Type: listenerType, Port: 853, Listen: "127.0.0.1"}, &stubDNSClient{})
		if err := listener.Start(); err == nil {
			t.Fatalf("%s listener started without certificate", listenerType)
		}
	}
}

func testCertificateFiles(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certPath := filepath.Join(directory, "server.crt")
	keyPath := filepath.Join(directory, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func TestDoTListenerTLSAndALPN(t *testing.T) {
	certPath, keyPath := testCertificateFiles(t)
	port := freeTCPPort(t)
	listener := NewDNS(&Config{
		Tag: "dot-test", Type: "dot", Listen: "127.0.0.1", Port: port, Network: "tcp",
		DNSCertificateFile: certPath, DNSKeyFile: keyPath,
	}, &stubDNSClient{ips: []bcnet.IP{{192, 0, 2, 10}}, ttl: 60})
	if err := listener.Start(); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{
		InsecureSkipVerify: true, // test-only self-signed certificate
		NextProtos:         []string{"dot"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != "dot" {
		t.Fatalf("DoT ALPN=%q, want dot", got)
	}
	query := dnsQuery(t, 90, dnsmessage.TypeA)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(query)))
	if writeAll(conn, length[:]) != nil || writeAll(conn, query) != nil {
		t.Fatal("failed to write DoT query")
	}
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if got := unpackDNS(t, response); got.ID != 90 || len(got.Answers) != 1 {
		t.Fatalf("DoT response id=%d answers=%d", got.ID, len(got.Answers))
	}
}

func TestDoHListenerNegotiatesHTTP2(t *testing.T) {
	certPath, keyPath := testCertificateFiles(t)
	port := freeTCPPort(t)
	listener := NewDNS(&Config{
		Tag: "doh-test", Type: "doh", Listen: "127.0.0.1", Port: port, Network: "tcp",
		DNSCertificateFile: certPath, DNSKeyFile: keyPath,
	}, &stubDNSClient{ips: []bcnet.IP{{192, 0, 2, 11}}, ttl: 60})
	if err := listener.Start(); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	query := dnsQuery(t, 91, dnsmessage.TypeA)
	request, err := http.NewRequest(http.MethodPost, "https://127.0.0.1:"+strconv.Itoa(port)+"/dns-query", bytes.NewReader(query))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/dns-message")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 {
		t.Fatalf("DoH status=%d protocol=%s", response.StatusCode, response.Proto)
	}
}
