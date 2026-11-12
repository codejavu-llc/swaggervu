package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/codejavu-llc/swaggervu/internal/spec"
	"github.com/getkin/kin-openapi/openapi3"
)

func TestInspectionFallbackWarning(t *testing.T) {
	const control = `{"openapi":"3.0.3","info":{"title":"x","version":"1"},"paths":{"/a":{"get":{"responses":{"200":{"description":"ok"}}}},"/b":{"$ref":"#/paths/~1a"}},"components":{"schemas":{"Unused":{"type":"string"}}}}`
	const warning = "operation list may be incomplete: the description could not be fully resolved"
	fallback := strings.Replace(control, `"Unused":{"type":"string"}`, `"Unused":{"$ref":"schema.json"}`, 1)

	// The self-contained document is valid. The contrast only moves its unused
	// schema to an unsupported separate-file reference; both paths stay the same.
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(control))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}

	oldJSON, oldQuiet, oldOutput := flagJSON, flagQuiet, flagOutput
	t.Cleanup(func() { flagJSON, flagQuiet, flagOutput = oldJSON, oldQuiet, oldOutput })
	for _, input := range []struct {
		name        string
		data        string
		operations  []string
		wantWarning bool
	}{
		{"self-contained", control, []string{"GET /a", "GET /b"}, false},
		{"separate-file-reference", fallback, []string{"GET /a"}, true},
	} {
		for _, mode := range []struct {
			name  string
			json  bool
			quiet bool
		}{
			{"json", true, false},
			{"json-quiet", true, true},
			{"text", false, false},
			{"text-quiet", false, true},
		} {
			t.Run(input.name+"/"+mode.name, func(t *testing.T) {
				s, err := spec.Load([]byte(input.data), "./description.json")
				if err != nil {
					t.Fatal(err)
				}
				report := inspectSpec(s, "./description.json")
				if !reflect.DeepEqual(report.Endpoints, input.operations) {
					t.Fatalf("operations = %v; want %v", report.Endpoints, input.operations)
				}
				flagJSON, flagQuiet = mode.json, mode.quiet
				flagOutput = filepath.Join(t.TempDir(), "inventory.txt")
				if err := emitInspection(report); err != nil {
					t.Fatal(err)
				}
				output, err := os.ReadFile(flagOutput)
				if err != nil {
					t.Fatal(err)
				}
				if mode.json {
					var decoded inspectReport
					if err := json.Unmarshal(output, &decoded); err != nil {
						t.Fatal(err)
					}
					if decoded.SchemaVersion != "swaggervu.inspect/v1" || !reflect.DeepEqual(decoded.Endpoints, input.operations) {
						t.Fatalf("unexpected JSON inventory: %s", output)
					}
				} else {
					var operations []string
					for _, line := range strings.Split(string(output), "\n") {
						if strings.HasPrefix(line, "  GET ") {
							operations = append(operations, strings.TrimSpace(line))
						}
					}
					if !reflect.DeepEqual(operations, input.operations) {
						t.Fatalf("text operations = %v; want %v", operations, input.operations)
					}
				}
				wantCount := 0
				if input.wantWarning {
					wantCount = 1
				}
				if got := strings.Count(string(output), warning); got != wantCount {
					t.Errorf("incomplete-list warning count = %d; want %d; output:\n%s", got, wantCount, output)
				}
			})
		}
	}
}
