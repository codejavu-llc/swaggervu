package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestDiffRedactedOutput(t *testing.T) {
	// Artificial repeated-character values, never credentials for an account.
	markerA, markerB := "ghp_"+strings.Repeat("A", 36), "ghp_"+strings.Repeat("B", 36)
	pathA, pathB := "/example/"+markerA, "/example/"+markerB
	const hidden = "GET /example/[REDACTED]"
	cases := []struct {
		name     string
		before   []string
		after    []string
		added    []string
		removed  []string
		breaking bool
	}{
		{name: "empty"},
		{name: "unchanged", before: []string{pathA}, after: []string{pathA}},
		{name: "ordinary addition", after: []string{"/cakes"}, added: []string{"GET /cakes"}},
		{name: "ordinary removal", before: []string{"/cakes"}, removed: []string{"GET /cakes"}, breaking: true},
		{name: "artificial addition", after: []string{pathA}, added: []string{hidden}},
		{name: "artificial removal", before: []string{pathA}, removed: []string{hidden}, breaking: true},
		{name: "changed hidden value", before: []string{pathA}, after: []string{pathB}, added: []string{hidden}, removed: []string{hidden}, breaking: true},
		{name: "distinct hidden additions", after: []string{pathA, pathB}, added: []string{hidden, hidden}},
		{name: "mixed additions", after: []string{pathA, "/cakes"}, added: []string{"GET /cakes", hidden}},
	}
	oldJSON, oldOutput := flagJSON, flagOutput
	t.Cleanup(func() { flagJSON, flagOutput = oldJSON, oldOutput })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputs := make([]string, 0, 2)
			for i, paths := range [][]string{tc.before, tc.after} {
				entries := map[string]any{}
				for _, path := range paths {
					entries[path] = map[string]any{"get": map[string]any{
						"responses": map[string]any{"200": map[string]any{"description": "OK"}},
					}}
				}
				data, err := json.Marshal(map[string]any{
					"openapi": "3.0.3", "info": map[string]any{"title": "Artificial diff", "version": "1"}, "paths": entries,
				})
				if err != nil {
					t.Fatal(err)
				}
				// Check the fixture's validity separately from the command under test.
				doc, err := openapi3.NewLoader().LoadFromData(data)
				if err != nil {
					t.Fatal(err)
				}
				if err := doc.Validate(context.Background()); err != nil {
					t.Fatalf("invalid fixture: %v", err)
				}
				input := filepath.Join(t.TempDir(), fmt.Sprintf("input-%d.json", i))
				if err := os.WriteFile(input, data, 0600); err != nil {
					t.Fatal(err)
				}
				inputs = append(inputs, input)
			}
			for _, format := range []string{"json", "text"} {
				for _, destination := range []string{"stdout", "file"} {
					t.Run(format+"/"+destination, func(t *testing.T) {
						// Shared CLI flags and stdout require sequential tests.
						flagJSON, flagOutput = format == "json", ""
						out, err := os.CreateTemp(t.TempDir(), "stdout-*")
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = out.Close() })
						if destination == "file" {
							flagOutput = filepath.Join(t.TempDir(), "comparison.txt")
						}
						err = func() error {
							previous := os.Stdout
							os.Stdout = out
							defer func() { os.Stdout = previous }()
							return diffCmd.RunE(diffCmd, inputs)
						}()
						if err != nil {
							t.Fatal(err)
						}
						if err := out.Close(); err != nil {
							t.Fatal(err)
						}
						stdout, err := os.ReadFile(out.Name())
						if err != nil {
							t.Fatal(err)
						}
						body := stdout
						if destination == "file" {
							if len(stdout) != 0 {
								t.Fatalf("selected file unexpectedly also wrote stdout: %q", stdout)
							}
							body, err = os.ReadFile(flagOutput)
							if err != nil {
								t.Fatal(err)
							}
						}
						if strings.Contains(string(body), markerA) || strings.Contains(string(body), markerB) {
							t.Error("output contains an artificial matched value")
						}
						if format == "json" {
							var actual diffReport
							if err := json.Unmarshal(body, &actual); err != nil {
								t.Fatal(err)
							}
							want := diffReport{SchemaVersion: "swaggervu.diff/v1", Added: tc.added, Removed: tc.removed, Breaking: tc.breaking}
							if !reflect.DeepEqual(actual, want) {
								t.Errorf("report = %#v; want %#v", actual, want)
							}
						} else {
							var want strings.Builder
							for _, endpoint := range tc.added {
								fmt.Fprintln(&want, "+ "+endpoint)
							}
							for _, endpoint := range tc.removed {
								fmt.Fprintln(&want, "- "+endpoint)
							}
							fmt.Fprintf(&want, "added=%d removed=%d breaking=%t\n", len(tc.added), len(tc.removed), tc.breaking)
							if string(body) != want.String() {
								t.Errorf("text = %q; want %q", body, want.String())
							}
						}
					})
				}
			}
		})
	}
}
