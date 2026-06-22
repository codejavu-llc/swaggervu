// Package spec loads and normalizes Swagger 2.0 / OpenAPI 3.x definitions from
// JSON, YAML, or JavaScript-embedded sources into a single openapi3 document.
package spec

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/yaml.v3"
)

// Kind identifies the family/version of a parsed definition.
type Kind string

const (
	KindSwagger2  Kind = "Swagger 2.0"
	KindOpenAPI30 Kind = "OpenAPI 3.0"
	KindOpenAPI31 Kind = "OpenAPI 3.1"
	KindUnknown   Kind = "Unknown"
)

// Spec is a normalized API definition. Doc is always a v3 document (v2 is
// converted on load) so downstream code only handles one shape.
type Spec struct {
	Kind      Kind
	Version   string // raw version string e.g. "2.0", "3.0.1"
	Title     string
	Doc       *openapi3.T
	Raw       map[string]any
	SourceURL string
}

var jsObjectRe = regexp.MustCompile(`(?s)(?:let|const|var)\s+\w+\s*=\s*(\{.*?\})\s*[;\n]`)

// Detect inspects raw bytes and returns the Kind plus the raw version string
// without fully parsing. Handles JSON and YAML (a JSON superset).
func Detect(b []byte) (Kind, string) {
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil || m == nil {
		// Maybe the spec is embedded in JS — try to pull it out.
		if obj := extractFromJS(b); obj != nil {
			m = obj
		} else {
			return KindUnknown, ""
		}
	}
	if v, ok := m["swagger"].(string); ok {
		return KindSwagger2, v
	}
	if v, ok := m["openapi"].(string); ok {
		switch {
		case strings.HasPrefix(v, "3.1"):
			return KindOpenAPI31, v
		case strings.HasPrefix(v, "3.0"):
			return KindOpenAPI30, v
		default:
			return KindOpenAPI30, v
		}
	}
	return KindUnknown, ""
}

// Load parses raw bytes into a normalized Spec.
func Load(b []byte, sourceURL string) (*Spec, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(b, &raw); err != nil || raw == nil {
		if obj := extractFromJS(b); obj != nil {
			raw = obj
			// Re-marshal to JSON so kin-openapi can load it cleanly.
			if jb, err := json.Marshal(obj); err == nil {
				b = jb
			}
		} else {
			return nil, fmt.Errorf("not a valid JSON/YAML/JS spec: %w", err)
		}
	}

	kind, version := detectFromMap(raw)
	s := &Spec{Kind: kind, Version: version, Raw: raw, SourceURL: sourceURL}

	// Normalize bytes to JSON for the loader (handles YAML input).
	jsonBytes := b
	if !looksJSON(b) {
		if jb, err := yamlToJSON(raw); err == nil {
			jsonBytes = jb
		}
	}

	switch kind {
	case KindSwagger2:
		doc3, err := loadV2(jsonBytes)
		if err != nil {
			// Retry after sanitizing common real-world schema violations.
			if fixed, ok := sanitizeForLoad(jsonBytes); ok {
				doc3, err = loadV2(fixed)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("parse swagger 2.0: %w", err)
		}
		s.Doc = doc3
	default:
		doc3, err := loadV3(jsonBytes)
		if err != nil {
			if fixed, ok := sanitizeForLoad(jsonBytes); ok {
				doc3, err = loadV3(fixed)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("parse openapi: %w", err)
		}
		s.Doc = doc3
		if kind == KindUnknown && doc3.Paths != nil && doc3.Paths.Len() > 0 {
			s.Kind = KindOpenAPI30
		}
	}

	if s.Doc != nil && s.Doc.Info != nil {
		s.Title = s.Doc.Info.Title
	}
	return s, nil
}

// loadV3 parses OpenAPI 3.x bytes, falling back to a relaxed unmarshal so
// partially-invalid specs still yield their paths.
func loadV3(jsonBytes []byte) (*openapi3.T, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	if doc, err := loader.LoadFromData(jsonBytes); err == nil {
		return doc, nil
	}
	var d openapi3.T
	if err := json.Unmarshal(jsonBytes, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// loadV2 parses Swagger 2.0 bytes and converts to a v3 document.
func loadV2(jsonBytes []byte) (*openapi3.T, error) {
	var doc2 openapi2.T
	if err := json.Unmarshal(jsonBytes, &doc2); err != nil {
		return nil, err
	}
	return openapi2conv.ToV3(&doc2)
}

// sanitizeForLoad fixes the most common real-world schema violations that cause
// strict parsers to reject an otherwise-usable spec, and strips the security
// sections (not needed for endpoint enumeration / request generation) that are
// a frequent source of parse failures. Returns the fixed JSON and whether it
// changed anything.
func sanitizeForLoad(jsonBytes []byte) ([]byte, bool) {
	var m map[string]any
	if json.Unmarshal(jsonBytes, &m) != nil {
		return nil, false
	}
	changed := coerceScopes(m) // OAuth flow scopes: [] -> {}

	// Strip security definitions — these reference OAuth flows and auth schemes
	// that often violate the strict schema, and we don't need them to map/test
	// endpoints.
	for _, k := range []string{"security", "securityDefinitions"} {
		if _, ok := m[k]; ok {
			delete(m, k)
			changed = true
		}
	}
	if comp, ok := m["components"].(map[string]any); ok {
		if _, ok := comp["securitySchemes"]; ok {
			delete(comp, "securitySchemes")
			changed = true
		}
	}
	if !changed {
		return nil, false
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, false
	}
	return b, true
}

// coerceScopes recursively rewrites any "scopes" array into an empty object,
// the shape OpenAPI requires for OAuth flow scopes.
func coerceScopes(v any) bool {
	changed := false
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if k == "scopes" {
				if _, isArr := val.([]any); isArr {
					x[k] = map[string]any{}
					changed = true
					continue
				}
			}
			if coerceScopes(val) {
				changed = true
			}
		}
	case []any:
		for _, it := range x {
			if coerceScopes(it) {
				changed = true
			}
		}
	}
	return changed
}

// detectFromMap is Detect's logic on an already-parsed map.
func detectFromMap(m map[string]any) (Kind, string) {
	if v, ok := m["swagger"].(string); ok {
		return KindSwagger2, v
	}
	if v, ok := m["openapi"].(string); ok {
		switch {
		case strings.HasPrefix(v, "3.1"):
			return KindOpenAPI31, v
		case strings.HasPrefix(v, "3.0"):
			return KindOpenAPI30, v
		}
		return KindOpenAPI30, v
	}
	return KindUnknown, ""
}

// extractFromJS tries to pull an embedded spec object out of a swagger-ui JS bundle.
func extractFromJS(b []byte) map[string]any {
	s := string(b)
	for _, match := range jsObjectRe.FindAllStringSubmatch(s, -1) {
		obj := match[1]
		var m map[string]any
		if err := json.Unmarshal([]byte(jsObjectToJSON(obj)), &m); err != nil {
			continue
		}
		// Unwrap swagger-ui-express style wrappers.
		for _, key := range []string{"swaggerDoc", "spec"} {
			if inner, ok := m[key].(map[string]any); ok {
				m = inner
				break
			}
		}
		if _, ok := m["swagger"]; ok {
			return m
		}
		if _, ok := m["openapi"]; ok {
			return m
		}
	}
	return nil
}

var (
	trailingCommaRe = regexp.MustCompile(`,(\s*[}\]])`)
	bareKeyRe       = regexp.MustCompile(`([{,]\s*)([A-Za-z_][\w-]*)(\s*:)`)
)

// jsObjectToJSON best-effort converts a JS object literal into JSON.
func jsObjectToJSON(s string) string {
	s = strings.ReplaceAll(s, "'", "\"")
	s = bareKeyRe.ReplaceAllString(s, `$1"$2"$3`)
	s = trailingCommaRe.ReplaceAllString(s, "$1")
	return s
}

func looksJSON(b []byte) bool {
	t := strings.TrimSpace(string(b))
	return strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")
}

func yamlToJSON(m map[string]any) ([]byte, error) {
	return json.Marshal(normalizeYAML(m))
}

// normalizeYAML converts map[interface{}]interface{} (from YAML) into
// map[string]interface{} recursively so encoding/json can marshal it.
func normalizeYAML(v any) any {
	switch x := v.(type) {
	case map[any]any:
		out := map[string]any{}
		for k, val := range x {
			out[fmt.Sprintf("%v", k)] = normalizeYAML(val)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, val := range x {
			out[k] = normalizeYAML(val)
		}
		return out
	case []any:
		for i := range x {
			x[i] = normalizeYAML(x[i])
		}
		return x
	default:
		return v
	}
}
