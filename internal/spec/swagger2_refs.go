package spec

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/go-openapi/jsonpointer"
)

// resolveV2PathRefs expands same-document Path Item references before conversion.
// kin-openapi's Swagger 2 converter copies operations and parameters but drops
// PathItem.Ref. Resolving first also keeps referenced Swagger 2 parameters and
// response schemas on the normal conversion path. The original raw input stays
// unchanged. External references remain unsupported.
func resolveV2PathRefs(doc *openapi2.T, data []byte) error {
	var raw map[string]any
	resolved := make(map[string]*openapi2.PathItem)
	for _, path := range slices.Sorted(maps.Keys(doc.Paths)) {
		item := doc.Paths[path]
		if item == nil || item.Ref == "" {
			continue
		}
		if raw == nil {
			if err := json.Unmarshal(data, &raw); err != nil {
				return err
			}
		}
		target, err := resolveV2PathRef(item.Ref, raw, resolved)
		if err != nil {
			return fmt.Errorf("path %q: %w", path, err)
		}
		doc.Paths[path] = target
	}
	return nil
}

// Follow chains iteratively, remembering resolved targets and rejecting cycles.
// A reference selects the referenced Path Item; sibling fields are not merged.
// Swagger 2 leaves conflicting reference/sibling definitions undefined.
func resolveV2PathRef(ref string, raw map[string]any, resolved map[string]*openapi2.PathItem) (*openapi2.PathItem, error) {
	seen := make(map[string]bool)
	var chain []string
	var target *openapi2.PathItem
	for {
		if !strings.HasPrefix(ref, "#") {
			return nil, fmt.Errorf("external path item references are not supported: %q", ref)
		}
		// A URI fragment is percent-decoded before JSON Pointer's ~1/~0 decoding.
		// PathUnescape preserves literal plus signs, unlike QueryUnescape.
		fragment, err := url.PathUnescape(strings.TrimPrefix(ref, "#"))
		if err != nil {
			return nil, fmt.Errorf("invalid path item reference %q: %w", ref, err)
		}
		if cached := resolved[fragment]; cached != nil {
			target = cached
			break
		}
		if seen[fragment] {
			return nil, fmt.Errorf("path item reference cycle at %q", ref)
		}
		seen[fragment] = true
		chain = append(chain, fragment)
		pointer, err := jsonpointer.New(fragment)
		if err != nil {
			return nil, fmt.Errorf("invalid path item reference %q: %w", ref, err)
		}
		value, _, err := pointer.Get(raw)
		if err != nil {
			return nil, fmt.Errorf("resolve path item reference %q: %w", ref, err)
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("path item reference %q must point to an object", ref)
		}
		// json.Unmarshal accepts unknown Path Item fields as extensions. Check the
		// target's shape first so a pointer to the document or its info object
		// cannot silently turn into an empty operation list. An empty object and
		// an extension-only Path Item are both valid.
		for _, key := range slices.Sorted(maps.Keys(object)) {
			if !isV2PathItemField(key) {
				return nil, fmt.Errorf("path item reference %q points to an object with unsupported field %q", ref, key)
			}
		}
		body, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		target = new(openapi2.PathItem)
		if err := json.Unmarshal(body, target); err != nil {
			return nil, fmt.Errorf("decode path item reference %q: %w", ref, err)
		}
		if target.Ref == "" {
			break
		}
		ref = target.Ref
	}
	for _, fragment := range chain {
		resolved[fragment] = target
	}
	return target, nil
}

func isV2PathItemField(key string) bool {
	if strings.HasPrefix(key, "x-") {
		return true
	}
	switch key {
	case "$ref", "get", "put", "post", "delete", "options", "head", "patch", "parameters":
		return true
	default:
		return false
	}
}
