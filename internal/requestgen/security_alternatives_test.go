package requestgen

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/codejavu-llc/swaggervu/internal/spec"
	"github.com/getkin/kin-openapi/openapi3"
)

func TestRequiresAuthAlternatives(t *testing.T) {
	tests := []struct {
		name      string
		document  string
		operation string
		want      bool
	}{
		{name: "no_declaration", want: false},
		{name: "empty_document_list", document: `[]`, want: false},
		{name: "inherited_requirement", document: `[{"bearer":[]}]`, want: true},
		{name: "empty_operation_overrides_required", document: `[{"bearer":[]}]`, operation: `[]`, want: false},
		{name: "empty_object_overrides_required", document: `[{"bearer":[]}]`, operation: `[{}]`, want: false},
		{name: "operation_optional_empty_first", operation: `[{}, {"bearer":[]}]`, want: false},
		{name: "operation_optional_empty_last", operation: `[{"bearer":[]}, {}]`, want: false},
		{name: "document_optional_empty_first", document: `[{}, {"bearer":[]}]`, want: false},
		{name: "document_optional_empty_last", document: `[{"bearer":[]}, {}]`, want: false},
		{name: "required_operation_overrides_optional", document: `[{}, {"bearer":[]}]`, operation: `[{"bearer":[]}]`, want: true},
		{name: "two_required_alternatives", operation: `[{"bearer":[]}, {"apiKey":[]}]`, want: true},
		{name: "combined_schemes", operation: `[{"bearer":[], "apiKey":[]}]`, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := map[string]any{
				"responses": map[string]any{"200": map[string]any{"description": "OK"}},
			}
			input := map[string]any{
				"openapi": "3.0.3",
				"info":    map[string]any{"title": "Security alternatives", "version": "1"},
				"servers": []any{map[string]any{"url": "https://example.invalid"}},
				"paths":   map[string]any{"/optional": map[string]any{"get": op}},
				"components": map[string]any{"securitySchemes": map[string]any{
					"bearer": map[string]any{"type": "http", "scheme": "bearer"},
					"apiKey": map[string]any{"type": "apiKey", "in": "header", "name": "X-Example-Key"},
				}},
			}
			if tt.document != "" {
				input["security"] = json.RawMessage(tt.document)
			}
			if tt.operation != "" {
				op["security"] = json.RawMessage(tt.operation)
			}
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			// Check validity separately from SwaggerVu's parser and generator.
			loader := openapi3.NewLoader()
			doc, err := loader.LoadFromData(raw)
			if err != nil {
				t.Fatalf("load test fixture: %v", err)
			}
			if err := doc.Validate(context.Background()); err != nil {
				t.Fatalf("invalid test fixture: %v", err)
			}
			s, err := spec.Load(raw, "./security.json")
			if err != nil {
				t.Fatal(err)
			}
			reqs := Build(s, DefaultOptions())
			if len(reqs) != 1 {
				t.Fatalf("generated %d requests; want one", len(reqs))
			}
			req := reqs[0]
			if req.Method != "GET" || req.Path != "/optional" || req.URL != "https://example.invalid/optional" {
				t.Fatalf("unexpected generated operation: %+v", req)
			}
			if req.RequiresAuth != tt.want {
				t.Errorf("RequiresAuth = %v; want %v", req.RequiresAuth, tt.want)
			}
		})
	}
}
