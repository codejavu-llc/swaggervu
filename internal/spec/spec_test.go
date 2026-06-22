package spec

import "testing"

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
