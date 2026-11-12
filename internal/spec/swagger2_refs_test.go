package spec_test

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/codejavu-llc/swaggervu/internal/detect"
	"github.com/codejavu-llc/swaggervu/internal/spec"
)

// These are equivalent descriptions. A reference changes the spelling of the
// definition, not the operation's path or its presence in the inventory.
func TestLoadSwagger2PathReferences(t *testing.T) {
	for _, name := range []string{
		"swagger2-path-inline.json", "swagger2-path-reference.json",
		"swagger2-path-inline.yaml", "swagger2-path-reference.yaml",
	} {
		t.Run(name, func(t *testing.T) {
			body, err := os.ReadFile("testdata/" + name)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := spec.Load(body, "./"+name)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"GET /cakes", "GET /cakes-copy"}
			if got := detect.Endpoints(doc); !reflect.DeepEqual(got, want) {
				t.Fatalf("operations = %v; want %v", got, want)
			}
			if strings.Contains(name, "reference") {
				paths := doc.Raw["paths"].(map[string]any)
				if got := paths["/cakes-copy"].(map[string]any)["$ref"]; got != "#/paths/~1cakes" {
					t.Fatalf("raw input reference changed: %v", got)
				}
			}
		})
	}
}

func TestLoadSwagger2PathReferenceDetails(t *testing.T) {
	const get = `{"get":{"responses":{"200":{"description":"OK"}}}}`
	cases := []struct {
		name  string
		paths string
		want  []string
	}{
		{"chain", `{"/copy":{"$ref":"#/paths/~1middle"},"/middle":{"$ref":"#/paths/~1cakes"},"/cakes":` + get + `}`,
			[]string{"GET /cakes", "GET /copy", "GET /middle"}},
		{"tilde and slash", `{"/copy":{"$ref":"#/paths/~1cakes~0special"},"/cakes~special":` + get + `}`,
			[]string{"GET /cakes~special", "GET /copy"}},
		{"percent-encoded space", `{"/copy":{"$ref":"#/paths/~1tea%20cakes"},"/tea cakes":` + get + `}`,
			[]string{"GET /copy", "GET /tea cakes"}},
		{"literal plus", `{"/copy":{"$ref":"#/paths/~1tea+cake"},"/tea+cake":` + get + `}`,
			[]string{"GET /copy", "GET /tea+cake"}},
		{"empty path item", `{"/copy":{"$ref":"#/paths/~1empty"},"/empty":{}}`, nil},
		{"extension-only path item", `{"/copy":{"$ref":"#/paths/~1empty"},"/empty":{"x-note":"valid"}}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"swagger":"2.0","info":{"title":"Local references","version":"1"},"paths":` + tc.paths + `}`
			doc, err := spec.Load([]byte(body), "./local.json")
			if err != nil {
				t.Fatal(err)
			}
			if got := detect.Endpoints(doc); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("operations = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestLoadSwagger2PathReferencePreservesDetails(t *testing.T) {
	// An extension can hold a shared Path Item. Resolve it while it is still
	// Swagger 2, so parameters and response schemas are converted normally.
	body := []byte(`{
		"swagger":"2.0","info":{"title":"Shared path","version":"1"},
		"paths":{"/cakes":{"$ref":"#/x-shared-paths/cakes"}},
		"x-shared-paths":{"cakes":{
			"parameters":[{"name":"size","in":"query","type":"integer"}],
			"get":{"parameters":[{"name":"kind","in":"query","type":"string"}],
			"responses":{"200":{"description":"OK","schema":{"$ref":"#/definitions/Cake"}}}}
		}},
		"definitions":{"Cake":{"type":"object","properties":{"name":{"type":"string"}}}}
	}`)
	doc, err := spec.Load(body, "./shared.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := detect.Endpoints(doc); !reflect.DeepEqual(got, []string{"GET /cakes"}) {
		t.Fatalf("operations = %v; want GET /cakes", got)
	}
	item := doc.Doc.Paths.Value("/cakes")
	if len(item.Parameters) != 1 || item.Parameters[0].Value == nil || item.Parameters[0].Value.Name != "size" {
		t.Fatalf("shared path parameter lost: %#v", item.Parameters)
	}
	if len(item.Get.Parameters) != 1 || item.Get.Parameters[0].Value == nil || item.Get.Parameters[0].Value.Name != "kind" {
		t.Fatalf("operation parameter lost: %#v", item.Get.Parameters)
	}
	response := item.Get.Responses.Status(200)
	if response == nil || response.Value == nil || response.Value.Content.Get("application/json") == nil {
		t.Fatal("response schema content lost")
	}
	schema := response.Value.Content.Get("application/json").Schema
	if schema == nil || schema.Value == nil || schema.Value.Properties["name"] == nil {
		t.Fatal("response schema reference was not converted and resolved")
	}
}

func TestLoadSwagger2PathReferenceErrors(t *testing.T) {
	cases := []struct{ name, paths, message string }{
		{"missing", `{"/copy":{"$ref":"#/paths/~1missing"}}`, "path"},
		{"cycle", `{"/a":{"$ref":"#/paths/~1b"},"/b":{"$ref":"#/paths/~1a"}}`, "cycle"},
		{"wrong target type", `{"/copy":{"$ref":"#/info/title"}}`, "object"},
		{"document object is not path item", `{"/copy":{"$ref":"#"}}`, "unsupported field"},
		{"info object is not path item", `{"/copy":{"$ref":"#/info"}}`, "unsupported field"},
		{"schema object is not path item", `{"/copy":{"$ref":"#/definitions/Cake"}}`, "unsupported field"},
		{"invalid pointer", `{"/copy":{"$ref":"#missing"}}`, "reference"},
		{"separate file stays unsupported", `{"/copy":{"$ref":"other.json#/paths/~1cakes"}}`, "external"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"swagger":"2.0","info":{"title":"Invalid local reference","version":"1"},"definitions":{"Cake":{"type":"object"}},"paths":` + tc.paths + `}`
			_, err := spec.Load([]byte(body), "./invalid.json")
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.message) {
				t.Fatalf("error = %v; want a clear %q error", err, tc.message)
			}
		})
	}
}
