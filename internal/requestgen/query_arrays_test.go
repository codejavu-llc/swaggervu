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

func TestBuildQueryArraySerialization(t *testing.T) {
	trueValue, falseValue := true, false
	cases := []struct {
		name    string
		value   any
		style   string
		explode *bool
		want    url.Values
	}{
		{name: "default form explodes", value: []any{"tea", "cake"}, want: url.Values{"tags": {"tea", "cake"}}},
		{name: "explicit form explodes", value: []any{"tea", "cake"}, style: "form", explode: &trueValue, want: url.Values{"tags": {"tea", "cake"}}},
		{name: "form does not explode", value: []any{"tea", "cake"}, style: "form", explode: &falseValue, want: url.Values{"tags": {"tea,cake"}}},
		{name: "default style does not explode", value: []any{"tea", "cake"}, explode: &falseValue, want: url.Values{"tags": {"tea,cake"}}},
		{name: "space delimited", value: []any{"tea", "cake"}, style: "spaceDelimited", explode: &falseValue, want: url.Values{"tags": {"tea cake"}}},
		{name: "pipe delimited", value: []any{"tea", "cake"}, style: "pipeDelimited", explode: &falseValue, want: url.Values{"tags": {"tea|cake"}}},
		{name: "escaped repeated values", value: []any{"green tea", "crème & cake"}, want: url.Values{"tags": {"green tea", "crème & cake"}}},
		{name: "repeated identical values", value: []any{"tea", "tea"}, want: url.Values{"tags": {"tea", "tea"}}},
		{name: "empty array", value: []any{}, want: url.Values{}},
		{name: "scalar control", value: "tea", want: url.Values{"tags": {"tea"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			schema := map[string]any{"type": "string", "enum": []any{tc.value}}
			if _, isArray := tc.value.([]any); isArray {
				schema["type"] = "array"
				schema["items"] = map[string]any{"type": "string"}
			}
			parameter := map[string]any{"name": "tags", "in": "query", "schema": schema}
			if tc.style != "" {
				parameter["style"] = tc.style
			}
			if tc.explode != nil {
				parameter["explode"] = *tc.explode
			}
			raw, err := json.Marshal(map[string]any{
				"openapi": "3.0.3",
				"info":    map[string]any{"title": "Query arrays", "version": "1"},
				"servers": []any{map[string]any{"url": "https://example.invalid"}},
				"paths": map[string]any{"/items": map[string]any{"get": map[string]any{
					"parameters": []any{parameter},
					"responses":  map[string]any{"200": map[string]any{"description": "OK"}},
				}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			doc, err := openapi3.NewLoader().LoadFromData(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := doc.Validate(context.Background()); err != nil {
				t.Fatalf("invalid fixture: %v", err)
			}
			s, err := spec.Load(raw, "./query-arrays.json")
			if err != nil {
				t.Fatal(err)
			}
			requests := Build(s, DefaultOptions())
			if len(requests) != 1 {
				t.Fatalf("got %d requests; want one", len(requests))
			}
			u, err := url.Parse(requests[0].URL)
			if err != nil {
				t.Fatal(err)
			}
			if u.Scheme != "https" || u.Host != "example.invalid" || u.Path != "/items" {
				t.Fatalf("wrong request URL: %s", requests[0].URL)
			}
			got, err := url.ParseQuery(u.RawQuery)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("decoded query = %#v; want %#v; URL = %q", got, tc.want, requests[0].URL)
			}
		})
	}
}
