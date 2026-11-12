package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/codejavu-llc/swaggervu/internal/output"
)

func TestScanCommandRequestBudget(t *testing.T) {
	// Command flags are package globals, so these cases must not run in parallel.
	oldConcurrency, oldTimeout, oldRate := flagConcurrency, flagTimeout, flagRate
	oldHosts, oldPrivate := flagAllowedHosts, flagAllowPrivate
	oldMax, oldBody := flagMaxRequests, flagMaxBodyMB
	oldJSON, oldOutput, oldQuiet := flagJSON, flagOutput, flagQuiet
	oldActive, oldShowAll, oldURL, oldBase := scanActive, scanShowAll, scanURL, scanBase
	oldLogger, oldContext := log, scanCmd.Context()
	t.Cleanup(func() {
		flagConcurrency, flagTimeout, flagRate = oldConcurrency, oldTimeout, oldRate
		flagAllowedHosts, flagAllowPrivate = oldHosts, oldPrivate
		flagMaxRequests, flagMaxBodyMB = oldMax, oldBody
		flagJSON, flagOutput, flagQuiet = oldJSON, oldOutput, oldQuiet
		scanActive, scanShowAll, scanURL, scanBase = oldActive, oldShowAll, oldURL, oldBase
		log = oldLogger
		scanCmd.SetContext(oldContext)
	})
	flagConcurrency, flagTimeout, flagRate = 1, 1, 0
	flagAllowedHosts, flagAllowPrivate = []string{"127.0.0.1"}, true
	flagMaxBodyMB, flagJSON, flagQuiet = 1, true, true
	scanActive, scanShowAll, scanURL, scanBase = true, true, "", ""
	log = &output.Logger{Quiet: true}
	for _, tt := range []struct {
		name  string
		local bool
		limit int64
		runs  int
		want  []string
	}{
		{"local file limit one", true, 1, 1, []string{"GET /api/data"}},
		{"URL limit two", false, 2, 1, []string{"GET /spec.json", "GET /api/data"}},
		{"URL limit one", false, 1, 1, []string{"GET /spec.json"}},
		{"URL unlimited", false, 0, 1, []string{"GET /spec.json", "GET /api/data"}},
		{"new invocation gets fresh allowance", false, 2, 2, []string{"GET /spec.json", "GET /api/data", "GET /spec.json", "GET /api/data"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var received []string
			var description []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				received = append(received, r.Method+" "+r.URL.Path)
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/spec.json":
					_, _ = w.Write(description)
				case "/api/data":
					_, _ = w.Write([]byte(`{"ok":true}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()
			description = []byte(fmt.Sprintf(`{"openapi":"3.0.3","info":{"title":"Budget control","version":"1"},"servers":[{"url":%q}],"paths":{"/api/data":{"get":{"responses":{"200":{"description":"OK"}}}}}}`, srv.URL))
			input := srv.URL + "/spec.json"
			if tt.local {
				input = filepath.Join(t.TempDir(), "description.json")
				if err := os.WriteFile(input, description, 0600); err != nil {
					t.Fatal(err)
				}
			}
			flagMaxRequests = tt.limit
			flagOutput = filepath.Join(t.TempDir(), "results.json")
			for i := 0; i < tt.runs; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				scanCmd.SetContext(ctx)
				if err := rootCmd.PersistentPreRunE(scanCmd, []string{input}); err != nil {
					cancel()
					t.Fatal(err)
				}
				err := scanCmd.RunE(scanCmd, []string{input})
				cancel()
				if err != nil {
					t.Fatal(err)
				}
			}
			mu.Lock()
			got := append([]string(nil), received...)
			mu.Unlock()
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("received %v, want %v", got, tt.want)
			}
		})
	}
}
