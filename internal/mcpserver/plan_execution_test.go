package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunScanUsesOnlyPlannedRequestsAfterRepeated404s(t *testing.T) {
	var specHits, plannedHits, rootHits atomic.Int64
	var document []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/spec.json":
			specHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(document)
		case strings.HasPrefix(r.URL.Path, "/v1/"):
			plannedHits.Add(1)
			http.Error(w, "missing", http.StatusNotFound)
		default:
			rootHits.Add(1)
			http.Error(w, "missing", http.StatusNotFound)
		}
	}))
	defer server.Close()

	paths := map[string]any{}
	for _, path := range []string{"/a", "/b", "/c", "/d", "/e"} {
		paths[path] = map[string]any{"get": map[string]any{
			"responses": map[string]any{"200": map[string]any{"description": "OK"}},
		}}
	}
	var err error
	document, err = json.Marshal(map[string]any{
		"openapi": "3.0.3",
		"info":    map[string]string{"title": "Plan execution", "version": "1"},
		"servers": []map[string]string{{"url": server.URL + "/v1"}},
		"paths":   paths,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{
		AllowedRoots: []string{t.TempDir()},
		AllowedHosts: []string{"127.0.0.1"},
		AllowPrivate: true,
		Active:       true,
		MaxRequests:  20,
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	source := server.URL + "/spec.json"
	plan, err := service.plan(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Requests) != 5 {
		t.Fatalf("plan has %d requests, want 5", len(plan.Requests))
	}
	for _, req := range plan.Requests {
		u, err := url.Parse(req.URL)
		if err != nil || !strings.HasPrefix(u.Path, "/v1/") {
			t.Fatalf("unexpected planned request: %#v", req)
		}
	}
	if _, err := service.runScan(ctx, source); err != nil {
		t.Fatal(err)
	}
	if got := specHits.Load(); got != 2 {
		t.Errorf("description fetched %d times, want once per tool call", got)
	}
	if got := plannedHits.Load(); got != int64(len(plan.Requests)) {
		t.Errorf("executed %d planned requests, want %d", got, len(plan.Requests))
	}
	if got := rootHits.Load(); got != 0 {
		t.Errorf("executed %d unplanned host-root requests", got)
	}
}
