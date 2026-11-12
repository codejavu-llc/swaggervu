package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDiffSwagger2PathReferences(t *testing.T) {
	oldJSON, oldOutput := flagJSON, flagOutput
	t.Cleanup(func() { flagJSON, flagOutput = oldJSON, oldOutput })
	flagJSON = true
	dir := t.TempDir()
	inline, err := filepath.Abs("../internal/spec/testdata/swagger2-path-inline.json")
	if err != nil {
		t.Fatal(err)
	}
	reference, err := filepath.Abs("../internal/spec/testdata/swagger2-path-reference.json")
	if err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`{"swagger":"2.0","info":{"title":"Empty","version":"1"},"paths":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	ops := []string{"GET /cakes", "GET /cakes-copy"}
	cases := []struct {
		name, before, after string
		added, removed      []string
		breaking            bool
	}{
		{"identical direct", inline, inline, nil, nil, false},
		{"identical reference", reference, reference, nil, nil, false},
		{"equivalent", inline, reference, nil, nil, false},
		{"equivalent swapped", reference, inline, nil, nil, false},
		{"added", empty, reference, ops, nil, false},
		{"removed", reference, empty, nil, ops, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flagOutput = filepath.Join(dir, tc.name+".json")
			if err := diffCmd.RunE(diffCmd, []string{tc.before, tc.after}); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(flagOutput)
			if err != nil {
				t.Fatal(err)
			}
			var got diffReport
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatal(err)
			}
			want := diffReport{SchemaVersion: "swaggervu.diff/v1", Added: tc.added, Removed: tc.removed, Breaking: tc.breaking}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("diff = %#v; want %#v", got, want)
			}
		})
	}
}
