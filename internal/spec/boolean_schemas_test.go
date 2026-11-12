package spec

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/yaml.v3"
)

const booleanSchemaDocument = `{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/x":{"get":{"responses":{"200":{"description":"ok"}}}}},"components":{"schemas":{"Any":%s}}}`

func loadBooleanSchemaTest(t *testing.T, body []byte, method string) *Spec {
	t.Helper()
	var original map[string]any
	if err := yaml.Unmarshal(body, &original); err != nil {
		t.Fatal(err)
	}
	s, err := Load(body, "./artificial.json")
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind != KindOpenAPI31 || s.Version != "3.1.0" || s.Title != "x" {
		t.Fatalf("unexpected document identity: %s %s %s", s.Kind, s.Version, s.Title)
	}
	if s.Doc.Paths == nil || s.Doc.Paths.Len() != 1 || s.Doc.Paths.Value("/x") == nil {
		t.Fatal("expected exactly path /x")
	}
	operations := s.Doc.Paths.Value("/x").Operations()
	if len(operations) != 1 || operations[method] == nil {
		t.Fatalf("expected exactly %s /x", method)
	}
	if !reflect.DeepEqual(s.Raw, original) {
		t.Fatal("loading changed the original raw document")
	}
	return s
}

func TestLoad31BooleanComponents(t *testing.T) {
	for _, form := range []string{"{}", "true", "false"} {
		for _, format := range []string{"JSON", "YAML"} {
			t.Run(form+"/"+format, func(t *testing.T) {
				body := []byte(fmt.Sprintf(booleanSchemaDocument, form))
				if format == "YAML" {
					body = []byte("openapi: 3.1.0\ninfo: {title: x, version: '1'}\npaths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\ncomponents:\n  schemas:\n    Any: " + form + "\n")
				}
				s := loadBooleanSchemaTest(t, body, "GET")
				schema := s.Doc.Components.Schemas["Any"].Value
				if schema == nil {
					t.Fatal("component schema was lost")
				}
				// A boolean schema constrains data; it is not an invalid document.
				for _, value := range []any{nil, true, false, float64(7), "cake", []any{"tea"}, map[string]any{"name": "cake"}} {
					err := schema.VisitJSON(value, openapi3.EnableJSONSchema2020())
					if (err == nil) != (form != "false") {
						t.Fatalf("schema %s changed meaning for %#v: %v", form, value, err)
					}
				}
			})
		}
	}
}

func TestLoad31BooleanLocations(t *testing.T) {
	for _, tt := range []struct {
		name, method, operation, components, pointer string
		allowed                                      bool
	}{
		{"response", "GET", `"responses":{"200":{"description":"ok","content":{"application/json":{"schema":true}}}}`, `{}`, "paths|/x|get|responses|200|content|application/json|schema", true},
		{"request body", "POST", `"requestBody":{"content":{"application/json":{"schema":false}}},"responses":{"200":{"description":"ok"}}`, `{}`, "paths|/x|post|requestBody|content|application/json|schema", false},
		{"parameter", "GET", `"parameters":[{"name":"value","in":"query","schema":true}],"responses":{"200":{"description":"ok"}}`, `{}`, "paths|/x|get|parameters|0|schema", true},
		{"header", "GET", `"responses":{"200":{"description":"ok","headers":{"X-Value":{"schema":false}}}}`, `{}`, "paths|/x|get|responses|200|headers|X-Value|schema", false},
		{"schema reference", "GET", `"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Any"}}}}}`, `{"schemas":{"Any":true}}`, "components|schemas|Any", true},
		{"response reference", "GET", `"responses":{"200":{"$ref":"#/components/responses/Reply"}}`, `{"responses":{"Reply":{"description":"ok","content":{"application/json":{"schema":false}}}}}`, "components|responses|Reply|content|application/json|schema", false},
		{"body reference", "POST", `"requestBody":{"$ref":"#/components/requestBodies/Body"},"responses":{"200":{"description":"ok"}}`, `{"requestBodies":{"Body":{"content":{"application/json":{"schema":true}}}}}`, "components|requestBodies|Body|content|application/json|schema", true},
		{"parameter reference", "GET", `"parameters":[{"$ref":"#/components/parameters/Value"}],"responses":{"200":{"description":"ok"}}`, `{"parameters":{"Value":{"name":"value","in":"query","schema":false}}}`, "components|parameters|Value|schema", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(fmt.Sprintf(`{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/x":{%q:{%s}}},"components":%s}`, strings.ToLower(tt.method), tt.operation, tt.components))
			s := loadBooleanSchemaTest(t, body, tt.method)
			want := any(map[string]any{})
			if !tt.allowed {
				want = map[string]any{"not": map[string]any{}}
			}
			if got := booleanTestJSONAt(t, s.Doc, tt.pointer); !reflect.DeepEqual(got, want) {
				t.Fatalf("schema at %s = %#v, want %#v", tt.pointer, got, want)
			}
			if tt.name == "schema reference" {
				ref := s.Doc.Paths.Value("/x").Get.Responses.Value("200").Value.Content["application/json"].Schema
				if ref.Value == nil || ref.Value != s.Doc.Components.Schemas["Any"].Value {
					t.Fatal("ordinary in-document schema reference did not resolve")
				}
			}
		})
	}
}

func TestLoad31BooleanNested(t *testing.T) {
	s := loadBooleanSchemaTest(t, []byte(fmt.Sprintf(booleanSchemaDocument, `{
  "properties":{"allowed":true,"blocked":false},
  "items":true,"not":false,"allOf":[true],"anyOf":[false,true],"oneOf":[true,false],
  "prefixItems":[true,false],"contains":false,"propertyNames":true,
  "patternProperties":{"^a":true},"dependentSchemas":{"name":false},
  "if":true,"then":false,"else":true,"$defs":{"Item":false},"contentSchema":true,
  "additionalProperties":false,"unevaluatedItems":false,"unevaluatedProperties":true
}`)), "GET")
	for _, path := range []string{"properties|allowed", "items", "allOf|0", "anyOf|1", "oneOf|0", "prefixItems|0", "propertyNames", "patternProperties|^a", "if", "else", "contentSchema"} {
		if got := booleanTestJSONAt(t, s.Doc, "components|schemas|Any|"+path); !reflect.DeepEqual(got, map[string]any{}) {
			t.Errorf("true schema at %s = %#v", path, got)
		}
	}
	for _, path := range []string{"properties|blocked", "not", "anyOf|0", "oneOf|1", "prefixItems|1", "contains", "dependentSchemas|name", "then", "$defs|Item"} {
		if got := booleanTestJSONAt(t, s.Doc, "components|schemas|Any|"+path); !reflect.DeepEqual(got, map[string]any{"not": map[string]any{}}) {
			t.Errorf("false schema at %s = %#v", path, got)
		}
	}
	for path, want := range map[string]bool{"additionalProperties": false, "unevaluatedItems": false, "unevaluatedProperties": true} {
		if got := booleanTestJSONAt(t, s.Doc, "components|schemas|Any|"+path); got != want {
			t.Errorf("already supported boolean at %s changed: %#v", path, got)
		}
	}
}

func TestLoad31BooleanDataUnchanged(t *testing.T) {
	body := []byte(`{
  "openapi":"3.1.0",
  "info":{"title":"x","version":"1"},
  "x-data":{"schema":true,"schemas":{"Any":false}},
  "paths":{
    "/x":{
      "get":{
        "deprecated":true,
        "parameters":[{"name":"flag","in":"query","required":true,"schema":{"type":"boolean","default":true,"example":false,"enum":[true,false]}}],
        "responses":{
          "200":{
            "description":"ok",
            "content":{
              "application/json":{
                "schema":{"$ref":"#/components/schemas/Any"},
                "example":{"schema":false,"properties":{"value":true}},
                "examples":{"flag":{"value":true}}
              }
            }
          }
        }
      }
    }
  },
  "components":{
    "schemas":{
      "Any":true,
      "Data":{"default":{"schema":true},"example":{"schema":false},"const":false,"examples":[true,false],"x-extra":{"items":false}}
    }
  }
}`)
	s := loadBooleanSchemaTest(t, body, "GET")
	for path, want := range map[string]any{
		"x-data":                                                                  map[string]any{"schema": true, "schemas": map[string]any{"Any": false}},
		"paths|/x|get|deprecated":                                                 true,
		"paths|/x|get|parameters|0|required":                                      true,
		"paths|/x|get|parameters|0|schema|default":                                true,
		"paths|/x|get|parameters|0|schema|example":                                false,
		"paths|/x|get|parameters|0|schema|enum":                                   []any{true, false},
		"paths|/x|get|responses|200|content|application/json|example":             map[string]any{"schema": false, "properties": map[string]any{"value": true}},
		"paths|/x|get|responses|200|content|application/json|examples|flag|value": true,
		"components|schemas|Data|default":                                         map[string]any{"schema": true},
		"components|schemas|Data|example":                                         map[string]any{"schema": false},
		"components|schemas|Data|const":                                           false,
		"components|schemas|Data|examples":                                        []any{true, false},
		"components|schemas|Data|x-extra":                                         map[string]any{"items": false},
	} {
		if got := booleanTestJSONAt(t, s.Doc, path); !reflect.DeepEqual(got, want) {
			t.Errorf("ordinary data at %s changed: %#v; want %#v", path, got, want)
		}
	}
}

func TestLoadBooleanVersionBoundary(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		valid      bool
	}{
		{"3.0 object control", strings.Replace(fmt.Sprintf(booleanSchemaDocument, `{}`), "3.1.0", "3.0.3", 1), true},
		{"3.0 boolean remains invalid", strings.Replace(fmt.Sprintf(booleanSchemaDocument, `true`), "3.1.0", "3.0.3", 1), false},
		{"3.0 nested boolean remains invalid", strings.Replace(fmt.Sprintf(booleanSchemaDocument, `{"properties":{"flag":true}}`), "3.1.0", "3.0.3", 1), false},
		{"3.0 response boolean remains invalid", `{"openapi":"3.0.3","info":{"title":"x","version":"1"},"paths":{"/x":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":false}}}}}}}}`, false},
		{"3.0 YAML boolean remains invalid", "openapi: 3.0.3\ninfo: {title: x, version: '1'}\npaths: {}\ncomponents:\n  schemas:\n    Any: true\n", false},
		{"3.0 ordinary booleans stay valid", `{"openapi":"3.0.3","info":{"title":"x","version":"1"},"paths":{"/x":{"get":{"deprecated":true,"responses":{"200":{"description":"ok"}}}}},"components":{"schemas":{"Any":{"type":"object","additionalProperties":false,"default":{"flag":true}}}}}`, true},
		{"2.0 object control", `{"swagger":"2.0","info":{"title":"x","version":"1"},"paths":{},"definitions":{"Any":{}}}`, true},
		{"2.0 boolean remains invalid", `{"swagger":"2.0","info":{"title":"x","version":"1"},"paths":{},"definitions":{"Any":true}}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load([]byte(tt.body), "./artificial.json")
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v, error=%v", tt.valid, err)
			}
		})
	}
}

func booleanTestJSONAt(t *testing.T, value any, path string) any {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var node any
	if err := json.Unmarshal(b, &node); err != nil {
		t.Fatal(err)
	}
	for _, key := range strings.Split(path, "|") {
		switch v := node.(type) {
		case map[string]any:
			var ok bool
			node, ok = v[key]
			if !ok {
				t.Fatalf("missing %s in %s", key, path)
			}
		case []any:
			var i int
			if _, err := fmt.Sscanf(key, "%d", &i); err != nil || i < 0 || i >= len(v) {
				t.Fatalf("invalid array index in %s", path)
			}
			node = v[i]
		default:
			t.Fatalf("cannot follow %s in %s", key, path)
		}
	}
	return node
}
