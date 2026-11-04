package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/codejavu-llc/swaggervu/internal/output"
	"github.com/codejavu-llc/swaggervu/internal/scan"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/spf13/cobra"
)

func TestScanIncompleteNotice(t *testing.T) {
	oldLog := log
	oldConcurrency, oldRate, oldTimeout := flagConcurrency, flagRate, flagTimeout
	oldProxy, oldHeaders, oldHosts := flagProxy, flagHeaders, flagAllowedHosts
	oldPrivate, oldLimit, oldBody := flagAllowPrivate, flagMaxRequests, flagMaxBodyMB
	oldOrigins, oldOutput, oldJSON, oldQuiet := flagAuthOrigins, flagOutput, flagJSON, flagQuiet
	oldURL, oldRisk, oldBase, oldAll := scanURL, scanRisk, scanBase, scanShowAll
	oldMD, oldAuth, oldEmit, oldActive := scanMD, scanAuth, scanEmit, scanActive
	t.Cleanup(func() {
		log = oldLog
		flagConcurrency, flagRate, flagTimeout = oldConcurrency, oldRate, oldTimeout
		flagProxy, flagHeaders, flagAllowedHosts = oldProxy, oldHeaders, oldHosts
		flagAllowPrivate, flagMaxRequests, flagMaxBodyMB = oldPrivate, oldLimit, oldBody
		flagAuthOrigins, flagOutput, flagJSON, flagQuiet = oldOrigins, oldOutput, oldJSON, oldQuiet
		scanURL, scanRisk, scanBase, scanShowAll = oldURL, oldRisk, oldBase, oldAll
		scanMD, scanAuth, scanEmit, scanActive = oldMD, oldAuth, oldEmit, oldActive
	})

	tests := []struct {
		name, profile, shortReply string
		limit                     int64
		quiet                     bool
		requests, rows            int
		budgetStops, otherErrors  int
	}{
		{name: "complete", profile: "ordinary", limit: 2, requests: 2, rows: 2},
		{name: "limit-one", profile: "ordinary", limit: 1, requests: 1, rows: 1, budgetStops: 1},
		{name: "limit-one-quiet", profile: "ordinary", limit: 1, quiet: true, requests: 1, rows: 1, budgetStops: 1},
		{name: "unselected-post", profile: "empty", limit: 1},
		{name: "comparison-complete", profile: "comparison", limit: 2, requests: 2, rows: 1},
		{name: "comparison-limit", profile: "comparison", limit: 1, requests: 1, rows: 1, budgetStops: 1},
		{name: "response-read-error", profile: "single", shortReply: "first", limit: 2, requests: 1, otherErrors: 1},
		{name: "comparison-second-read-error", profile: "comparison", shortReply: "second", limit: 2, requests: 2, rows: 1, otherErrors: 1},
		{name: "comparison-first-read-error", profile: "comparison", shortReply: "first", limit: 2, requests: 1, otherErrors: 1},
		{name: "two-budget-stops", profile: "multiple", limit: 1, requests: 1, rows: 1, budgetStops: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			type received struct{ method, path, marker string }
			var mu sync.Mutex
			var requests []received
			const body = `{"ok":true}`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				marker := r.Header.Get("X-Lab-Comparison")
				mu.Lock()
				requests = append(requests, received{r.Method, r.URL.Path, marker})
				mu.Unlock()
				size := len(body)
				if (tc.shortReply == "first" && marker == "") || (tc.shortReply == "second" && marker == "second") {
					size++ // A small incomplete reply must be reported as a read error.
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Length", strconv.Itoa(size))
				w.WriteHeader(http.StatusOK)
				if r.Method != http.MethodHead {
					_, _ = w.Write([]byte(body))
				}
			}))
			t.Cleanup(server.Close)
			operation := map[string]any{"responses": map[string]any{"200": map[string]any{"description": "OK"}}}
			paths := map[string]any{"/read": map[string]any{"get": operation}}
			switch tc.profile {
			case "ordinary":
				paths["/head"] = map[string]any{"head": operation}
				paths["/write"] = map[string]any{"post": operation}
			case "empty":
				paths = map[string]any{"/write": map[string]any{"post": operation}}
			case "multiple":
				paths["/a"] = map[string]any{"get": operation}
				paths["/b"] = map[string]any{"get": operation}
			}
			raw, err := json.Marshal(map[string]any{
				"openapi": "3.0.3", "info": map[string]any{"title": "Completion notice", "version": "1"},
				"servers": []any{map[string]any{"url": server.URL}}, "paths": paths,
			})
			if err != nil {
				t.Fatal(err)
			}
			loader := openapi3.NewLoader()
			doc, err := loader.LoadFromData(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := doc.Validate(context.Background()); err != nil {
				t.Fatalf("invalid artificial description: %v", err)
			}
			dir := t.TempDir()
			input := filepath.Join(dir, "description.json")
			if err := os.WriteFile(input, raw, 0600); err != nil {
				t.Fatal(err)
			}
			flagConcurrency, flagRate, flagTimeout = 1, 0, 2
			if tc.profile == "multiple" {
				flagConcurrency = 3
			}
			flagProxy, flagHeaders, flagAllowedHosts = "", nil, []string{"127.0.0.1"}
			flagAllowPrivate, flagMaxRequests, flagMaxBodyMB = true, tc.limit, 1
			flagAuthOrigins, flagOutput, flagJSON, flagQuiet = nil, filepath.Join(dir, "result.json"), true, tc.quiet
			scanURL, scanRisk, scanBase, scanShowAll = "", false, "", true
			scanMD, scanAuth, scanEmit, scanActive = false, nil, "", true
			if tc.profile == "comparison" {
				// This marker changes no access decision. Both replies are public.
				scanAuth = []string{"X-Lab-Comparison: second"}
				flagAuthOrigins = []string{server.URL}
			}
			log = &output.Logger{Quiet: tc.quiet}
			var diagnostics bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetErr(&diagnostics)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd.SetContext(ctx)
			if err := scanCmd.RunE(cmd, []string{input}); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			gotRequests := append([]received(nil), requests...)
			mu.Unlock()
			if len(gotRequests) != tc.requests {
				t.Fatalf("received %v; want %d requests", gotRequests, tc.requests)
			}
			for i, got := range gotRequests {
				wantMarker := ""
				if tc.profile == "comparison" && i == 1 {
					wantMarker = "second"
				}
				if got.marker != wantMarker || got.method == http.MethodPost || got.path == "/write" {
					t.Errorf("unexpected request: %+v", got)
				}
			}
			if tc.profile == "ordinary" && (gotRequests[0].method != "HEAD" || gotRequests[0].path != "/head") {
				t.Fatalf("first ordinary request = %+v; want HEAD /head", gotRequests[0])
			}
			data, err := os.ReadFile(flagOutput)
			if err != nil {
				t.Fatal(err)
			}
			var rows []scan.Result
			if err := json.Unmarshal(data, &rows); err != nil {
				t.Fatalf("JSON result was contaminated: %v; %s", err, data)
			}
			if len(rows) != tc.rows {
				t.Fatalf("got %d result rows; want %d", len(rows), tc.rows)
			}
			for _, row := range rows {
				wantAuth := 0
				if tc.name == "comparison-complete" {
					wantAuth = 200
				}
				if row.Status != 200 || row.AuthStatus != wantAuth || row.Interesting {
					t.Errorf("unexpected completed result: %+v", row)
				}
			}
			want := ""
			if tc.budgetStops+tc.otherErrors > 0 {
				want = fmt.Sprintf("warning: scan incomplete: %d request(s) stopped by the request limit; %d other request error(s). Results cover completed responses only.\n", tc.budgetStops, tc.otherErrors)
			}
			if diagnostics.String() != want {
				t.Errorf("completion notice = %q; want %q", diagnostics.String(), want)
			}
		})
	}
}
