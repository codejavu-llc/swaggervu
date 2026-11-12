package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codejavu-llc/swaggervu/internal/httpclient"
	"github.com/codejavu-llc/swaggervu/internal/requestgen"
	"github.com/codejavu-llc/swaggervu/internal/spec"
)

func TestBasepathFallbackRespectsSelectedServers(t *testing.T) {
	tests := []struct {
		name            string
		pathServer      bool
		sameOriginPath  bool
		operationServer bool
		override        bool
		wantSource      int64
		wantAPI         int64
		wantResults     int
	}{
		{name: "document base on source origin still falls back", wantSource: 10, wantResults: 10},
		{name: "path server on source origin at another path", sameOriginPath: true, wantSource: 5, wantResults: 5},
		{name: "path server on another origin", pathServer: true, wantAPI: 5, wantResults: 5},
		{name: "operation server on another origin", operationServer: true, wantAPI: 5, wantResults: 5},
		{name: "explicit base on another origin", override: true, wantAPI: 5, wantResults: 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sourceHits, apiHits atomic.Int64
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sourceHits.Add(1)
				if strings.HasPrefix(r.URL.Path, "/v1/") || strings.HasPrefix(r.URL.Path, "/v2/") {
					http.Error(w, "missing", http.StatusNotFound)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer source.Close()
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				apiHits.Add(1)
				http.Error(w, "missing", http.StatusNotFound)
			}))
			defer api.Close()

			paths := map[string]any{}
			for _, path := range []string{"/a", "/b", "/c", "/d", "/e"} {
				operation := map[string]any{"responses": map[string]any{"200": map[string]string{"description": "OK"}}}
				if tt.operationServer {
					operation["servers"] = []map[string]string{{"url": api.URL + "/v2"}}
				}
				item := map[string]any{"get": operation}
				if tt.pathServer || tt.sameOriginPath {
					server := api.URL
					if tt.sameOriginPath {
						server = source.URL
					}
					item["servers"] = []map[string]string{{"url": server + "/v2"}}
				}
				paths[path] = item
			}
			body, err := json.Marshal(map[string]any{
				"openapi": "3.0.3",
				"info":    map[string]string{"title": "Fallback routing", "version": "1"},
				"servers": []map[string]string{{"url": source.URL + "/v1"}},
				"paths":   paths,
			})
			if err != nil {
				t.Fatal(err)
			}
			s, err := spec.Load(body, source.URL+"/spec.json")
			if err != nil {
				t.Fatal(err)
			}
			opts := httpclient.DefaultOptions()
			opts.AllowPrivate = true
			opts.RatePerSecond = 0
			client, err := httpclient.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			genOpts := requestgen.DefaultOptions()
			if tt.override {
				genOpts.BaseURL = api.URL + "/v2"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			results := Run(ctx, client, s, Config{Concurrency: 1, GenOpts: genOpts}, nil)
			if got := sourceHits.Load(); got != tt.wantSource {
				t.Errorf("source received %d requests, want %d", got, tt.wantSource)
			}
			if got := apiHits.Load(); got != tt.wantAPI {
				t.Errorf("API received %d requests, want %d", got, tt.wantAPI)
			}
			if len(results) != tt.wantResults {
				t.Errorf("got %d scan results, want %d", len(results), tt.wantResults)
			}
		})
	}
}
