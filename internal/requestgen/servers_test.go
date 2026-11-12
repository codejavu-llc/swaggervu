package requestgen

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/codejavu-llc/swaggervu/internal/spec"
)

func TestBuildServerSelection(t *testing.T) {
	const origin = "https://example.invalid"
	tests := []struct {
		name              string
		document          []string
		path              []string
		operation         []string
		override          string
		wantGET, wantHEAD string
		wantSibling       string
	}{
		{"document", []string{origin + "/root/"}, nil, nil, "", origin + "/root/read", origin + "/root/read", origin + "/root/untouched"},
		{"path", []string{origin + "/root/"}, []string{origin + "/path/"}, nil, "", origin + "/path/read", origin + "/path/read", origin + "/root/untouched"},
		{"operation", []string{origin + "/root/"}, nil, []string{origin + "/operation/"}, "", origin + "/operation/read", origin + "/root/read", origin + "/root/untouched"},
		{"operation over path", []string{origin + "/root/"}, []string{origin + "/path/"}, []string{origin + "/operation/"}, "", origin + "/operation/read", origin + "/path/read", origin + "/root/untouched"},
		{"explicit override", []string{origin + "/root/"}, []string{origin + "/path/"}, []string{origin + "/operation/"}, origin + "/manual/", origin + "/manual/read", origin + "/manual/read", origin + "/manual/untouched"},
		{"first server at each level", []string{origin + "/root/", origin + "/other-root"}, []string{origin + "/path/", origin + "/other-path"}, []string{origin + "/operation/", origin + "/other-operation"}, "", origin + "/operation/read", origin + "/path/read", origin + "/root/untouched"},
		{"source origin fallback", nil, nil, nil, "", origin + "/read", origin + "/read", origin + "/untouched"},
		{"path without document server", nil, []string{origin + "/path/"}, nil, "", origin + "/path/read", origin + "/path/read", origin + "/untouched"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			operation := func() map[string]any {
				return map[string]any{"responses": map[string]any{"200": map[string]string{"description": "OK"}}}
			}
			setServers := func(target map[string]any, urls []string) {
				if len(urls) == 0 {
					return
				}
				servers := make([]map[string]string, len(urls))
				for i, value := range urls {
					servers[i] = map[string]string{"url": value}
				}
				target["servers"] = servers
			}
			get := operation()
			setServers(get, tt.operation)
			path := map[string]any{"get": get, "head": operation()}
			setServers(path, tt.path)
			document := map[string]any{
				"openapi": "3.0.3",
				"info":    map[string]string{"title": "Server selection", "version": "1"},
				"paths":   map[string]any{"/read": path, "/untouched": map[string]any{"get": operation()}},
			}
			setServers(document, tt.document)
			body, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			s, err := spec.Load(body, origin+"/descriptions/openapi.json")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Doc.Validate(context.Background()); err != nil {
				t.Fatalf("invalid test description: %v", err)
			}
			opts := DefaultOptions()
			opts.BaseURL = tt.override
			requests := Build(s, opts)
			want := map[string]string{"GET /read": tt.wantGET, "HEAD /read": tt.wantHEAD, "GET /untouched": tt.wantSibling}
			if len(requests) != len(want) {
				t.Fatalf("got %d requests, want %d", len(requests), len(want))
			}
			for _, request := range requests {
				key := request.Method + " " + request.Path
				expected, exists := want[key]
				if !exists {
					t.Errorf("unexpected or duplicate operation: %s", key)
				} else if request.URL != expected {
					t.Errorf("%s URL = %q, want %q", key, request.URL, expected)
				}
				delete(want, key)
			}
			if len(want) != 0 {
				t.Errorf("missing operations: %v", want)
			}
		})
	}
}
