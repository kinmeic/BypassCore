package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

type testBackend struct{}

func (testBackend) Status(context.Context) (any, error) { return map[string]any{"running": true}, nil }
func (testBackend) Ready(context.Context) (any, error)  { return map[string]any{"ready": true}, nil }
func (testBackend) Validate(context.Context, []byte) (any, error) {
	return map[string]any{"valid": true}, nil
}
func (testBackend) Reload(context.Context, []byte, ...string) (any, error) {
	return map[string]any{"reloaded": true}, nil
}
func (testBackend) Explain(_ context.Context, request RouteExplainRequest) (any, error) {
	return request, nil
}
func (testBackend) Resolve(_ context.Context, request DNSResolveRequest) (any, error) {
	return request, nil
}
func (testBackend) TCPProbe(_ context.Context, request TCPProbeRequest) (any, error) {
	return request, nil
}
func (testBackend) HandshakeProbe(_ context.Context, request HandshakeProbeRequest) (any, error) {
	return request, nil
}
func (testBackend) URLTest(_ context.Context, request URLTestRequest) (any, error) {
	return request, nil
}
func (testBackend) Observatory(context.Context) (any, error)     { return []any{}, nil }
func (testBackend) Metrics(context.Context) (any, error)         { return []any{}, nil }
func (testBackend) DNSResults(context.Context) (any, error)      { return []any{}, nil }
func (testBackend) DNSNFTSets(context.Context) (any, error)      { return []any{}, nil }
func (testBackend) ProbeDNSNFTSets(context.Context) (any, error) { return []any{}, nil }

func TestUnixControlServer(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	server, err := New(&Config{Enabled: true, Socket: socket}, testBackend{}, Capabilities{Version: "test", ConfigSchema: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	client := &http.Client{Transport: transport}
	response, err := client.Get("http://unix/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	var status map[string]any
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status["running"] != true {
		t.Fatalf("unexpected status: %#v", status)
	}
	for method, path := range map[string]string{
		http.MethodGet:  "/v1/dns/nftsets",
		http.MethodPost: "/v1/dns/nftsets/probe",
	} {
		request, _ := http.NewRequest(method, "http://unix"+path, nil)
		response, err = client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s %s status=%d", method, path, response.StatusCode)
		}
	}

	request, _ := http.NewRequest(http.MethodPost, "http://unix/v1/route/explain", bytes.NewBufferString(`{"destination":"tcp:example.com:443","unknown":true}`))
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodPost, "http://unix/v1/network/tcp-probe", bytes.NewBufferString(`{"host":"127.0.0.1","port":443}`))
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("TCP probe status=%d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodPost, "http://unix/v1/network/handshake-probe", bytes.NewBufferString(`{"outboundTag":"proxy"}`))
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("handshake probe status=%d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodPost, "http://unix/v1/network/url-test", bytes.NewBufferString(`{"url":"https://example.com/","outboundTag":"proxy","resolverTag":"url_test_direct"}`))
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("URL test status=%d", response.StatusCode)
	}
	var urlRequest URLTestRequest
	if err := json.NewDecoder(response.Body).Decode(&urlRequest); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if urlRequest.ResolverTag != "url_test_direct" {
		t.Fatalf("URL test resolver tag=%q", urlRequest.ResolverTag)
	}
}

func TestRefusesToReplaceRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := New(&Config{Enabled: true, Socket: path}, testBackend{}, Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err == nil {
		t.Fatal("expected refusal")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatalf("regular file changed: %q, %v", data, err)
	}
}

func TestCloseDoesNotRemoveReplacementSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "bc-control-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "control.sock")
	server, err := New(&Config{Enabled: true, Socket: path}, testBackend{}, Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	replacement.SetUnlinkOnClose(false)
	defer func() { _ = replacement.Close(); _ = os.Remove(path) }()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("replacement socket was removed: %v", err)
	}
}

func TestEquivalentConfigAppliesDefaults(t *testing.T) {
	left := &Config{Enabled: true}
	right := &Config{Enabled: true, Socket: DefaultSocket, Mode: "0660", MaxRequestBytes: defaultMaxRequestBytes, MaxInflightRequestBytes: defaultMaxInflightBytes, MaxConcurrentRequests: 16}
	if !EquivalentConfig(left, right) {
		t.Fatal("effective defaults were treated as a restart change")
	}
	if EquivalentConfig(left, &Config{Enabled: true, Socket: "/tmp/other.sock"}) {
		t.Fatal("different socket was treated as equivalent")
	}
}

type blockingBackend struct {
	testBackend
	started chan struct{}
	release chan struct{}
}

func (b *blockingBackend) Validate(context.Context, []byte) (any, error) {
	close(b.started)
	<-b.release
	return map[string]any{"valid": true}, nil
}

func TestMutationRequestsFailBusyInsteadOfQueueing(t *testing.T) {
	backend := &blockingBackend{started: make(chan struct{}), release: make(chan struct{})}
	server, err := New(&Config{Enabled: true, Socket: filepath.Join(t.TempDir(), "control.sock")}, backend, Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	handler := server.handler()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/config/validate", bytes.NewBufferString(`{}`)))
		close(done)
	}()
	<-backend.started
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/config/reload", bytes.NewBufferString(`{}`)))
	if recorder.Code != http.StatusServiceUnavailable || !bytes.Contains(recorder.Body.Bytes(), []byte(`"code":"busy"`)) {
		t.Fatalf("second mutation status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	close(backend.release)
	<-done
}

func TestControlResourceLimits(t *testing.T) {
	base := &Config{Enabled: true, Socket: "/tmp/control.sock"}
	tooLarge := *base
	tooLarge.MaxRequestBytes = 2<<20 + 1
	if err := Validate(&tooLarge); err == nil {
		t.Fatal("oversized request limit accepted")
	}
	tooConcurrent := *base
	tooConcurrent.MaxConcurrentRequests = 65
	if err := Validate(&tooConcurrent); err == nil {
		t.Fatal("oversized concurrency accepted")
	}
}
