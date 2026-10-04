package socks

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCredentialsDoNotOfferOrAcceptNoAuth(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		greeting := make([]byte, 3)
		_, _ = io.ReadFull(server, greeting)
		if greeting[0] != 5 || greeting[1] != 1 || greeting[2] != 2 {
			t.Errorf("greeting = %v, want only username/password", greeting)
		}
		_, _ = server.Write([]byte{5, 0}) // malicious/incorrect server choice
	}()
	handler := New("proxy", "unused", "user", "pass")
	if err := handler.authenticate(client); err == nil {
		t.Fatal("unoffered no-auth selection was accepted")
	}
	<-done
}

func TestNoCredentialsRejectsUnofferedUserPass(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		greeting := make([]byte, 3)
		_, _ = io.ReadFull(server, greeting)
		_, _ = server.Write([]byte{5, 2})
	}()
	if err := New("proxy", "unused", "", "").authenticate(client); err == nil || !strings.Contains(err.Error(), "unoffered") {
		t.Fatalf("unoffered user/pass selection: %v", err)
	}
	<-done
}
