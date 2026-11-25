package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alexvikman/nginx-proxy/internal/docker"
	"github.com/alexvikman/nginx-proxy/internal/socketproxy"
)

func TestFilterCheck(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	filter := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filter != "" {
			w.Header().Set(socketproxy.FilterHeader, filter)
			w.Header().Set(socketproxy.VersionHeader, "0.9.0")
		}
		w.Write([]byte("OK"))
	}))
	defer srv.Close()
	cli, err := docker.New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	check := newFilterCheck("1.0.0")

	check.run(t.Context(), cli) // Docker itself: no header
	if logs.Len() != 0 {
		t.Fatalf("nothing to report without a socket proxy, got %s", logs.String())
	}

	filter = "0123456789ab" // an older socket proxy
	check.run(t.Context(), cli)
	check.run(t.Context(), cli)
	if n := strings.Count(logs.String(), "level=ERROR"); n != 1 {
		t.Fatalf("a mismatch must be reported once, got %d: %s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "socket_proxy_version=0.9.0") {
		t.Errorf("the error should name the socket proxy's version: %s", logs.String())
	}

	logs.Reset()
	filter = check.want // upgraded
	check.run(t.Context(), cli)
	if !strings.Contains(logs.String(), "level=INFO") || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("a matching socket proxy should be noted, got %s", logs.String())
	}
}
