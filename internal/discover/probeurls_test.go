package discover

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/codejavu-llc/swaggervu/internal/httpclient"
)

// TestProbeURLsDirect verifies the Wayback/OSINT path: a candidate full URL is
// GET as-is and emitted, rather than being treated as a host and having the
// wordlist appended (the latent bug in the old --wayback seeding).
func TestProbeURLsDirect(t *testing.T) {
	const body = `{"openapi":"3.0.0","info":{"title":"Direct","version":"1"},"paths":{}}`
	// The spec lives at a deep path; the old code would append wordlist paths to
	// this and 404, never fetching the URL itself.
	const specPath = "/archived/deep/path/openapi.json"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == specPath {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, body)
			return
		}
		http.NotFound(w, r) // anything else (incl. appended wordlist paths) is 404
	}))
	defer srv.Close()

	client, err := httpclient.New(httpclient.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	specURL := srv.URL + specPath
	var hits []Hit
	ProbeURLs(context.Background(), client, []string{specURL}, 4, func(h Hit) {
		hits = append(hits, h)
	}, nil)

	if len(hits) != 1 {
		t.Fatalf("expected exactly 1 hit for the exact URL, got %d: %+v", len(hits), hits)
	}
	if hits[0].URL != specURL {
		t.Errorf("hit URL = %q, want %q (must probe the URL as-is, not append the wordlist)", hits[0].URL, specURL)
	}
	if !hits[0].IsSpec || hits[0].Title != "Direct" {
		t.Errorf("expected a parsed spec titled %q, got IsSpec=%v title=%q", "Direct", hits[0].IsSpec, hits[0].Title)
	}
}

// TestProbeURLsRejectsNonSpec confirms a plain 200 that is not Swagger-like is
// not emitted.
func TestProbeURLsRejectsNonSpec(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><body>just a page</body></html>")
	}))
	defer srv.Close()

	client, err := httpclient.New(httpclient.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	var hits []Hit
	ProbeURLs(context.Background(), client, []string{srv.URL + "/x"}, 2, func(h Hit) {
		hits = append(hits, h)
	}, nil)

	if len(hits) != 0 {
		t.Errorf("expected no hits for non-spec page, got %d: %+v", len(hits), hits)
	}
}
