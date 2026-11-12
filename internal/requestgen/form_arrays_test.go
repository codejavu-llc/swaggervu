package requestgen

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"testing"

	"github.com/codejavu-llc/swaggervu/internal/spec"
	"github.com/getkin/kin-openapi/openapi3"
)

func TestBuildFormArrays(t *testing.T) {
	const form = "application/x-www-form-urlencoded"
	list := []any{"tea", "cake"}
	cases := []struct {
		name      string
		mediaType string
		value     any
		itemType  string
		encoding  map[string]any
		extra     bool
		want      url.Values
	}{
		{name: "JSON control", mediaType: "application/json", value: list, itemType: "string"},
		{name: "form scalar control", mediaType: form, value: "tea", want: url.Values{"tags": {"tea"}}},
		{name: "explicit repeated", mediaType: form, value: list, itemType: "string", encoding: map[string]any{"style": "form", "explode": true}, want: url.Values{"tags": {"tea", "cake"}}},
		{name: "default encoding", mediaType: form, value: list, itemType: "string", want: url.Values{"tags": {"tea", "cake"}}},
		{name: "default explode", mediaType: form, value: list, itemType: "string", encoding: map[string]any{"style": "form"}, want: url.Values{"tags": {"tea", "cake"}}},
		{name: "default style", mediaType: form, value: list, itemType: "string", encoding: map[string]any{"explode": true}, want: url.Values{"tags": {"tea", "cake"}}},
		{name: "explicit joined", mediaType: form, value: list, itemType: "string", encoding: map[string]any{"style": "form", "explode": false}, want: url.Values{"tags": {"tea,cake"}}},
		{name: "joined default style", mediaType: form, value: list, itemType: "string", encoding: map[string]any{"explode": false}, want: url.Values{"tags": {"tea,cake"}}},
		{name: "spaces and Unicode", mediaType: form, value: []any{"green tea", "crème brûlée"}, itemType: "string", want: url.Values{"tags": {"green tea", "crème brûlée"}}},
		{name: "single item", mediaType: form, value: []any{"tea"}, itemType: "string", want: url.Values{"tags": {"tea"}}},
		{name: "repeated items", mediaType: form, value: []any{"tea", "tea"}, itemType: "string", want: url.Values{"tags": {"tea", "tea"}}},
		{name: "integer items", mediaType: form, value: []any{1, 2}, itemType: "integer", want: url.Values{"tags": {"1", "2"}}},
		{name: "boolean items", mediaType: form, value: []any{true, false}, itemType: "boolean", want: url.Values{"tags": {"true", "false"}}},
		{name: "empty repeated", mediaType: form, value: []any{}, itemType: "string", want: url.Values{}},
		{name: "empty joined", mediaType: form, value: []any{}, itemType: "string", encoding: map[string]any{"explode": false}, want: url.Values{}},
		{name: "mixed fields", mediaType: form, value: list, itemType: "string", extra: true, want: url.Values{"tags": {"tea", "cake"}, "note": {"small order"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			property := map[string]any{"type": "string", "enum": []any{tc.value}}
			if tc.itemType != "" {
				property["type"] = "array"
				property["items"] = map[string]any{"type": tc.itemType}
			}
			properties := map[string]any{"tags": property}
			bodyValue := map[string]any{"tags": tc.value}
			if tc.extra {
				properties["note"] = map[string]any{"type": "string", "enum": []any{"small order"}}
				bodyValue["note"] = "small order"
			}
			media := map[string]any{"schema": map[string]any{"type": "object", "properties": properties}}
			if tc.encoding != nil {
				media["encoding"] = map[string]any{"tags": tc.encoding}
			}
			raw, err := json.Marshal(map[string]any{
				"openapi": "3.0.3", "info": map[string]any{"title": "Form array control", "version": "1"},
				"servers": []any{map[string]any{"url": "https://example.invalid"}},
				"paths": map[string]any{"/orders": map[string]any{"post": map[string]any{
					"requestBody": map[string]any{"content": map[string]any{tc.mediaType: media}},
					"responses":   map[string]any{"200": map[string]any{"description": "OK"}},
				}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			// Validate both the fixture and intended value before exercising Build.
			doc, err := openapi3.NewLoader().LoadFromData(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := doc.Validate(context.Background()); err != nil {
				t.Fatalf("invalid fixture: %v", err)
			}
			bodySchema := doc.Paths.Value("/orders").Post.RequestBody.Value.Content[tc.mediaType].Schema.Value
			valueJSON, err := json.Marshal(bodyValue)
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := json.Unmarshal(valueJSON, &value); err != nil {
				t.Fatal(err)
			}
			if err := bodySchema.VisitJSON(value); err != nil {
				t.Fatalf("intended value does not match fixture: %v", err)
			}
			s, err := spec.Load(raw, "./form-array.json")
			if err != nil {
				t.Fatal(err)
			}
			opts := DefaultOptions()
			opts.IncludeRisk = true // Generate POST text; no requests are sent.
			requests := Build(s, opts)
			if len(requests) != 1 {
				t.Fatalf("got %d requests; want one", len(requests))
			}
			r := requests[0]
			if r.Method != "POST" || r.Path != "/orders" || r.URL != "https://example.invalid/orders" || r.ContentType != tc.mediaType {
				t.Fatalf("wrong request identity: %#v", r)
			}
			if tc.mediaType == "application/json" {
				var got any
				if err := json.Unmarshal([]byte(r.Body), &got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, value) {
					t.Fatalf("JSON body = %#v; want %#v", got, value)
				}
				return
			}
			got, err := url.ParseQuery(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("decoded form = %#v; want %#v; raw body = %q", got, tc.want, r.Body)
			}
		})
	}
}
