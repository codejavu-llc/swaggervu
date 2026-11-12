package spec

import (
	"bytes"
	"encoding/json"
	"strings"
)

// normalize31BooleanSchemas adapts schema booleans for kin-openapi's object-only
// SchemaRef. JSON Schema 2020-12 defines true as {} and false as {"not":{}}.
// Only schema locations are visited: examples, defaults and extensions are data.
// The separate decode also keeps Spec.Raw in its original form.
func normalize31BooleanSchemas(data []byte) ([]byte, bool) {
	if !json.Valid(data) {
		return nil, false
	}
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber() // Rewriting a schema must not round unrelated numbers.
	if err := decoder.Decode(&doc); err != nil {
		return nil, false
	}
	n := booleanSchemaNormalizer{}
	components, _ := doc["components"].(map[string]any)
	n.schemas(components["schemas"])
	for _, key := range []string{"parameters", "headers"} {
		visitSchemaMap(components[key], n.parameter)
	}
	for _, key := range []string{"requestBodies", "responses"} {
		visitSchemaMap(components[key], n.contentObject)
	}
	visitSchemaMap(components["callbacks"], n.callback)
	visitSchemaMap(components["pathItems"], n.pathItem)
	visitSchemaMap(doc["webhooks"], n.pathItem)
	paths, _ := doc["paths"].(map[string]any)
	for path, item := range paths {
		if strings.HasPrefix(path, "/") {
			n.pathItem(item)
		}
	}
	if !n.changed {
		return nil, false
	}
	normalized, err := json.Marshal(doc)
	return normalized, err == nil
}

type booleanSchemaNormalizer struct{ changed bool }

func (n *booleanSchemaNormalizer) schema(value any) any {
	if allowed, ok := value.(bool); ok {
		n.changed = true
		if allowed {
			return map[string]any{}
		}
		return map[string]any{"not": map[string]any{}}
	}
	m, ok := value.(map[string]any)
	if !ok {
		return value
	}
	for _, key := range []string{"not", "items", "contains", "propertyNames", "if", "then", "else", "contentSchema"} {
		n.schemaField(m, key)
	}
	for _, key := range []string{"properties", "patternProperties", "dependentSchemas", "$defs"} {
		n.schemas(m[key])
	}
	for _, key := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
		if children, ok := m[key].([]any); ok {
			for i, child := range children {
				children[i] = n.schema(child)
			}
		}
	}
	for _, key := range []string{"additionalProperties", "unevaluatedItems", "unevaluatedProperties"} {
		// These fields already accept booleans. Only visit their object form.
		if child, ok := m[key].(map[string]any); ok {
			n.schema(child)
		}
	}
	return value
}

func (n *booleanSchemaNormalizer) schemas(value any) {
	if schemas, ok := value.(map[string]any); ok {
		for name, schema := range schemas {
			schemas[name] = n.schema(schema)
		}
	}
}

func (n *booleanSchemaNormalizer) schemaField(m map[string]any, key string) {
	if schema, ok := m[key]; ok {
		m[key] = n.schema(schema)
	}
}

func visitSchemaMap(value any, visit func(any)) {
	if entries, ok := value.(map[string]any); ok {
		for _, entry := range entries {
			visit(entry)
		}
	}
}

func (n *booleanSchemaNormalizer) parameter(value any) {
	m, _ := value.(map[string]any)
	n.schemaField(m, "schema")
	n.content(m["content"])
}

func (n *booleanSchemaNormalizer) parameters(value any) {
	if parameters, ok := value.([]any); ok {
		for _, parameter := range parameters {
			n.parameter(parameter)
		}
	}
}

func (n *booleanSchemaNormalizer) contentObject(value any) {
	m, _ := value.(map[string]any)
	n.content(m["content"])
	visitSchemaMap(m["headers"], n.parameter)
}

func (n *booleanSchemaNormalizer) content(value any) {
	visitSchemaMap(value, func(media any) {
		m, _ := media.(map[string]any)
		n.schemaField(m, "schema")
		visitSchemaMap(m["encoding"], func(encoding any) {
			e, _ := encoding.(map[string]any)
			visitSchemaMap(e["headers"], n.parameter)
		})
	})
}

func (n *booleanSchemaNormalizer) pathItem(value any) {
	m, _ := value.(map[string]any)
	n.parameters(m["parameters"])
	for _, method := range []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"} {
		op, _ := m[method].(map[string]any)
		n.parameters(op["parameters"])
		n.contentObject(op["requestBody"])
		responses, _ := op["responses"].(map[string]any)
		for status, response := range responses {
			if !strings.HasPrefix(status, "x-") {
				n.contentObject(response)
			}
		}
		visitSchemaMap(op["callbacks"], n.callback)
	}
}

func (n *booleanSchemaNormalizer) callback(value any) {
	m, _ := value.(map[string]any)
	for expression, path := range m {
		if !strings.HasPrefix(expression, "x-") {
			n.pathItem(path)
		}
	}
}
