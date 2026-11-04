package spec

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestLoadEmptyInput(t *testing.T) {
	const valid = `{
  "openapi": "3.0.3",
  "info": {"title": "Cake Shop Practice API", "version": "1.0.0"},
  "paths": {
    "/health": {"get": {"responses": {"200": {"description": "OK"}}}},
    "/cakes": {"get": {"responses": {"200": {"description": "OK"}}}}
  }
}`
	const noOperations = `{"openapi":"3.0.3","info":{"title":"Empty API","version":"1"},"paths":{}}`
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(valid)); err != nil {
		t.Fatalf("invalid test document: %v", err)
	}
	tests := []struct {
		name         string
		input        string
		operations   []string
		errorText    string
		wrappedError bool
	}{
		{name: "valid_JSON", input: valid, operations: []string{"GET /cakes", "GET /health"}},
		{name: "valid_no_operations", input: noOperations, operations: []string{}},
		{name: "JS_object_fallback", input: "const description = " + compact.String() + ";\n", operations: []string{"GET /cakes", "GET /health"}},
		{name: "malformed_JSON", input: "{\"openapi\": \"3.0.3\", \"paths\": {\n", errorText: "not a valid JSON/YAML/JS spec:", wrappedError: true},
		{name: "zero_bytes", input: "", errorText: "empty or null document"},
		{name: "whitespace_only", input: "  \n  \n", errorText: "empty or null document"},
		{name: "JSON_null", input: "null", errorText: "empty or null document"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Load([]byte(tt.input), "./input.json")
			if tt.errorText != "" {
				if err == nil {
					t.Fatal("expected an input error")
				}
				if s != nil {
					t.Error("rejected input returned a Spec")
				}
				if !strings.Contains(err.Error(), tt.errorText) {
					t.Errorf("error %q does not explain %q", err, tt.errorText)
				}
				if strings.Contains(err.Error(), "%!") {
					t.Errorf("error contains a formatting diagnostic: %q", err)
				}
				if tt.wrappedError && errors.Unwrap(err) == nil {
					t.Error("underlying parse error was lost")
				}
				return
			}
			if err != nil {
				t.Fatalf("load valid input: %v", err)
			}
			if s == nil || s.Doc == nil || s.Doc.Paths == nil {
				t.Fatal("valid input did not return a document with paths")
			}
			var operations []string
			for path, item := range s.Doc.Paths.Map() {
				for method := range item.Operations() {
					operations = append(operations, strings.ToUpper(method)+" "+path)
				}
			}
			sort.Strings(operations)
			if !slices.Equal(operations, tt.operations) {
				t.Errorf("operations = %v; want %v", operations, tt.operations)
			}
		})
	}
}
