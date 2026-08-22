package spec

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const v2Spec = `{
  "swagger": "2.0",
  "info": {"title": "Test V2", "version": "1.0"},
  "host": "api.example.com",
  "basePath": "/v1",
  "schemes": ["https"],
  "paths": {
    "/users/{id}": {
      "get": {
        "parameters": [{"name": "id", "in": "path", "required": true, "type": "integer"}],
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}`

const v3Spec = `{
  "openapi": "3.0.1",
  "info": {"title": "Test V3", "version": "2.0"},
  "servers": [{"url": "https://api.example.com"}],
  "paths": {
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

const v3YAML = `openapi: 3.0.0
info:
  title: YAML API
  version: "1.0"
paths:
  /health:
    get:
      responses:
        '200':
          description: ok
`

func TestDetectAndLoadV2(t *testing.T) {
	k, v := Detect([]byte(v2Spec))
	if k != KindSwagger2 {
		t.Fatalf("expected Swagger 2.0, got %s", k)
	}
	if v != "2.0" {
		t.Fatalf("expected version 2.0, got %s", v)
	}
	s, err := Load([]byte(v2Spec), "https://api.example.com/swagger.json")
	if err != nil {
		t.Fatalf("load v2: %v", err)
	}
	if s.Title != "Test V2" {
		t.Fatalf("title mismatch: %s", s.Title)
	}
	if s.Doc.Paths == nil || s.Doc.Paths.Len() != 1 {
		t.Fatalf("expected 1 path after v2->v3 conversion")
	}
}

func TestDetectAndLoadV3(t *testing.T) {
	k, _ := Detect([]byte(v3Spec))
	if k != KindOpenAPI30 {
		t.Fatalf("expected OpenAPI 3.0, got %s", k)
	}
	s, err := Load([]byte(v3Spec), "https://api.example.com/openapi.json")
	if err != nil {
		t.Fatalf("load v3: %v", err)
	}
	if s.Doc.Paths.Len() != 1 {
		t.Fatalf("expected 1 path")
	}
}

func TestLoadYAML(t *testing.T) {
	k, _ := Detect([]byte(v3YAML))
	if k != KindOpenAPI30 {
		t.Fatalf("expected OpenAPI 3.0 from YAML, got %s", k)
	}
	s, err := Load([]byte(v3YAML), "")
	if err != nil {
		t.Fatalf("load yaml: %v", err)
	}
	if s.Title != "YAML API" {
		t.Fatalf("yaml title mismatch: %s", s.Title)
	}
}

func TestDetectOpenAPI32(t *testing.T) {
	body := []byte(`{"openapi":"3.2.0","info":{"title":"x","version":"1"},"paths":{"/widgets":{"get":{"responses":{"200":{"description":"ok"}}}}}}`)
	k, v := Detect(body)
	if k != KindOpenAPI32 || v != "3.2.0" {
		t.Fatalf("got kind=%q version=%q", k, v)
	}
	loaded, err := Load(body, "openapi-3.2.json")
	if err != nil {
		t.Fatalf("load OpenAPI 3.2: %v", err)
	}
	if loaded.Kind != KindOpenAPI32 || loaded.Doc == nil || loaded.Doc.Paths.Len() != 1 {
		t.Fatalf("unexpected OpenAPI 3.2 inventory: %#v", loaded)
	}
}

func FuzzLoadNeverPanics(f *testing.F) {
	f.Add([]byte(v2Spec))
	f.Add([]byte(v3Spec))
	f.Add([]byte(v3YAML))
	f.Add([]byte(`not a spec`))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = Load(body, "fuzz-input")
	})
}

func TestLoadDoesNotFetchExternalReferences(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()
	body := []byte(`{"openapi":"3.0.3","info":{"title":"x","version":"1"},"paths":{"/x":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"` + server.URL + `/schema.json"}}}}}}}}}`)
	if _, err := Load(body, "local.json"); err != nil {
		t.Fatalf("inventory should retain unresolved reference without fetching it: %v", err)
	}
	if requests != 0 {
		t.Fatalf("external reference triggered %d network request(s)", requests)
	}
}

func TestRelaxedLoadPreservesSecurityDeclarations(t *testing.T) {
	body := []byte(`{
  "openapi":"3.0.3",
  "info":{"title":"secured","version":"1"},
  "security":[{"oauth":[]}],
  "components":{"securitySchemes":{"oauth":{"type":"oauth2","flows":{"clientCredentials":{"tokenUrl":"https://example.com/token","scopes":[]}}}}},
  "paths":{"/private":{"get":{"responses":{"200":{"description":"ok"}}}}}
}`)
	loaded, err := Load(body, "secured.json")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Doc == nil || loaded.Doc.Components == nil || loaded.Doc.Components.SecuritySchemes["oauth"] == nil || len(loaded.Doc.Security) != 1 {
		t.Fatal("security declarations were lost during relaxed load")
	}
}
