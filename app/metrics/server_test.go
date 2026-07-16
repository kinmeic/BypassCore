package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	commonmetrics "github.com/eugene/bypasscore/common/metrics"
)

func TestMetricsHandlerAccessAndEndpoints(t *testing.T) {
	commonmetrics.ResetForTest()
	commonmetrics.Inc("bypasscore_test_total")
	server, err := New(&Config{EnablePprof: true})
	if err != nil {
		t.Fatal(err)
	}
	server.healthy.Store(true)
	for _, path := range []string{"/healthz", "/metrics", "/debug/pprof/"} {
		request := httptest.NewRequest(http.MethodGet, "http://metrics"+path, nil)
		request.RemoteAddr = "127.0.0.1:1234"
		recorder := httptest.NewRecorder()
		server.handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, recorder.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "http://metrics/healthz", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	recorder := httptest.NewRecorder()
	server.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unauthorized status=%d", recorder.Code)
	}
}

func TestMetricsRejectsUnsafeListener(t *testing.T) {
	server, _ := New(&Config{Listen: "0.0.0.0:0"})
	if err := server.Start(); err == nil {
		t.Fatal("unsafe metrics listener started")
	}
}
