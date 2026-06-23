package requestgen

import (
	"strings"
	"testing"

	"github.com/codejavu-llc/swaggervu/internal/spec"
)

const v3Spec = `{
  "openapi": "3.0.1",
  "info": {"title": "Test", "version": "1.0"},
  "servers": [{"url": "https://api.example.com"}],
  "paths": {
    "/users/{id}": {
      "get": {
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}],
        "responses": {"200": {"description": "ok"}}
      },
      "delete": {
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}],
        "responses": {"204": {"description": "gone"}}
      }
    },
    "/pets": {
      "post": {
        "requestBody": {"content": {"application/json": {"schema": {
          "type": "object",
          "properties": {"name": {"type": "string"}, "email": {"type": "string"}}
        }}}},
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}`

func TestBuildDefaultIsReadOnly(t *testing.T) {
	s, err := spec.Load([]byte(v3Spec), "")
	if err != nil {
		t.Fatal(err)
	}
	reqs := Build(s, DefaultOptions())
	for _, r := range reqs {
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			t.Fatalf("default build must be read-only, got %s %s", r.Method, r.URL)
		}
	}
	// Only GET /users/{id} is non-mutating in the fixture.
	if len(reqs) != 1 {
		t.Fatalf("expected 1 read-only request by default, got %d", len(reqs))
	}
}

func TestBuildRiskIncludesMutating(t *testing.T) {
	s, _ := spec.Load([]byte(v3Spec), "")
	opts := DefaultOptions()
	opts.IncludeRisk = true
	reqs := Build(s, opts)
	var hasPost, hasDelete bool
	for _, r := range reqs {
		hasPost = hasPost || r.Method == "POST"
		hasDelete = hasDelete || r.Method == "DELETE"
	}
	if !hasPost || !hasDelete {
		t.Fatalf("--risk should include POST and DELETE; got %d reqs", len(reqs))
	}
}

func TestPathParamSubstituted(t *testing.T) {
	s, _ := spec.Load([]byte(v3Spec), "")
	reqs := Build(s, DefaultOptions())
	var getReq *Request
	for i := range reqs {
		if reqs[i].Method == "GET" {
			getReq = &reqs[i]
		}
	}
	if getReq == nil {
		t.Fatal("no GET request generated")
	}
	if strings.Contains(getReq.URL, "{id}") {
		t.Fatalf("path param not substituted: %s", getReq.URL)
	}
	if !strings.HasPrefix(getReq.URL, "https://api.example.com/users/") {
		t.Fatalf("unexpected URL: %s", getReq.URL)
	}
}

const securedSpec = `{
  "openapi": "3.0.1",
  "info": {"title": "Secured", "version": "1.0"},
  "servers": [{"url": "https://api.example.com"}],
  "security": [{"bearerAuth": []}],
  "paths": {
    "/private": {"get": {"responses": {"200": {"description": "ok"}}}},
    "/public":  {"get": {"security": [], "responses": {"200": {"description": "ok"}}}}
  }
}`

func TestRequiresAuthFromSpec(t *testing.T) {
	s, err := spec.Load([]byte(securedSpec), "")
	if err != nil {
		t.Fatal(err)
	}
	reqs := Build(s, DefaultOptions())
	got := map[string]bool{}
	for _, r := range reqs {
		got[r.Path] = r.RequiresAuth
	}
	if !got["/private"] {
		t.Error("/private inherits document-level security and must require auth")
	}
	if got["/public"] {
		t.Error("/public has explicit empty security and must NOT require auth")
	}
}

func TestContextAwareBodyValues(t *testing.T) {
	s, _ := spec.Load([]byte(v3Spec), "")
	opts := DefaultOptions()
	opts.IncludeRisk = true // POST bodies are only generated with --risk
	reqs := Build(s, opts)
	var post *Request
	for i := range reqs {
		if reqs[i].Method == "POST" {
			post = &reqs[i]
		}
	}
	if post == nil {
		t.Fatal("no POST request")
	}
	if !strings.Contains(post.Body, "@example.com") {
		t.Fatalf("email field should use email value, body=%s", post.Body)
	}
}
