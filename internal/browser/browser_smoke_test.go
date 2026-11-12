//go:build browser_smoke

package browser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestChromeFindSpec(t *testing.T) {
	const doc = `{"openapi":"3.0.3","info":{"title":"Local fixture","version":"1"},"paths":{"/health":{"get":{"responses":{"200":{"description":"OK"}}}}}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/spec.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(doc))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<script>fetch('/spec.json').then(r => r.json())</script>`))
	}))
	defer server.Close()
	result, err := FindSpec(context.Background(), server.URL, false, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.Spec == nil || result.SpecURL != server.URL+"/spec.json" {
		t.Fatalf("spec=%v url=%q candidates=%v", result.Spec, result.SpecURL, result.Candidates)
	}
}
