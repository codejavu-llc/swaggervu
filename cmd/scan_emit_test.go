package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestScanEmitBaseURL(t *testing.T) {
	// These checks call the print-only command handler. They never execute the
	// generated text. Do not run in parallel: flags and stdout are shared.
	oldURL, oldBase, oldEmit := scanURL, scanBase, scanEmit
	oldRisk, oldActive, oldQuiet := scanRisk, scanActive, log.Quiet
	oldMaxBody := flagMaxBodyMB
	t.Cleanup(func() {
		scanURL, scanBase, scanEmit = oldURL, oldBase, oldEmit
		scanRisk, scanActive, log.Quiet = oldRisk, oldActive, oldQuiet
		flagMaxBodyMB = oldMaxBody
	})
	scanURL, scanRisk, scanActive, log.Quiet, flagMaxBodyMB = "", false, false, true, 1

	const description = `{
		"openapi": "3.0.3",
		"info": {"title": "Printed address example", "version": "1"},
		"servers": [{"url": "https://example.invalid/original"}],
		"paths": {
			"/read": {
				"get": {"responses": {"200": {"description": "OK"}}},
				"head": {"responses": {"200": {"description": "OK"}}}
			},
			"/write": {"post": {"responses": {"200": {"description": "OK"}}}}
		}
	}`
	// Check the input independently of the command's request-generation path.
	doc, err := openapi3.NewLoader().LoadFromData([]byte(description))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("invalid test description: %v", err)
	}
	input := filepath.Join(t.TempDir(), "read.json")
	if err := os.WriteFile(input, []byte(description), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, base, wantURL string
	}{
		{"description control", "", "https://example.invalid/original/read"},
		{"path override", "https://example.invalid/override", "https://example.invalid/override/read"},
		{"trailing slash", "https://example.invalid/override/", "https://example.invalid/override/read"},
		{"address override", "https://preview.example.invalid/manual", "https://preview.example.invalid/manual/read"},
	}
	for _, format := range []string{"curl", "sqlmap"} {
		for _, tc := range cases {
			t.Run(format+"/"+tc.name, func(t *testing.T) {
				scanBase, scanEmit = tc.base, format
				out, err := os.CreateTemp(t.TempDir(), "printed-*")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = out.Close() })
				err = func() error {
					previous := os.Stdout
					os.Stdout = out
					defer func() { os.Stdout = previous }()
					return scanCmd.RunE(scanCmd, []string{input})
				}()
				if err != nil {
					t.Fatal(err)
				}
				if err := out.Close(); err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(out.Name())
				if err != nil {
					t.Fatal(err)
				}
				want := "curl --fail-with-body -sS -X GET '" + tc.wantURL + "'\n" +
					"curl --fail-with-body -sS -X HEAD '" + tc.wantURL + "'\n"
				if format == "sqlmap" {
					want = "sqlmap -u '" + tc.wantURL + "' --batch\n" +
						"sqlmap -u '" + tc.wantURL + "' --batch --method=HEAD\n"
				}
				// Exact output also ensures POST stays omitted without --risk.
				if string(got) != want {
					t.Fatalf("printed output = %q; want %q", got, want)
				}
			})
		}
	}
}
