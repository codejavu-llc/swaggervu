package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDiffOutput(t *testing.T) {
	oldJSON, oldOutput := flagJSON, flagOutput
	t.Cleanup(func() { flagJSON, flagOutput = oldJSON, oldOutput })
	input := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(input, []byte(`{"openapi":"3.0.3","info":{"title":"Output control","version":"1"},"paths":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	formats := []struct {
		name string
		json bool
		want string
	}{
		{"json", true, "{\n  \"schema_version\": \"swaggervu.diff/v1\",\n  \"breaking\": false\n}\n"},
		{"text", false, "added=0 removed=0 breaking=false\n"},
	}
	for _, format := range formats {
		for _, mode := range []string{"stdout", "closed stdout", "selected file"} {
			t.Run(format.name+"/"+mode, func(t *testing.T) {
				// Do not run in parallel: the CLI flags and os.Stdout are shared.
				flagJSON, flagOutput = format.json, ""
				out, err := os.CreateTemp(t.TempDir(), "stdout-*")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = out.Close() })
				if mode != "stdout" {
					if err := out.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "selected file" {
					flagOutput = filepath.Join(t.TempDir(), "comparison.txt")
				}
				err = func() error {
					previous := os.Stdout
					os.Stdout = out
					defer func() { os.Stdout = previous }()
					return diffCmd.RunE(diffCmd, []string{input, input})
				}()
				if mode == "closed stdout" {
					if !errors.Is(err, os.ErrClosed) {
						t.Fatalf("got error %v; want the closed output error", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				path := flagOutput
				if mode == "stdout" {
					if err := out.Close(); err != nil {
						t.Fatal(err)
					}
					path = out.Name()
				}
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != format.want {
					t.Fatalf("output = %q; want %q", got, format.want)
				}
			})
		}
	}
}
