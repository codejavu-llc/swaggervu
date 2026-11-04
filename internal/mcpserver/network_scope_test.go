package mcpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestMCPNetworkRequiresStartupHost(t *testing.T) {
	var requests atomic.Int64
	var document []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/spec.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(document)
	}))
	defer server.Close()
	document = []byte(fmt.Sprintf(`{"openapi":"3.0.3","info":{"title":"Local MCP control","version":"1"},"servers":[{"url":%q}],"paths":{"/a":{"get":{"responses":{"200":{"description":"OK"}}}}}}`, server.URL))
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("invalid artificial description: %v", err)
	}
	root := t.TempDir()
	local := filepath.Join(root, "local.json")
	if err := os.WriteFile(local, document, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, tool                  string
		remote, allowHost, canceled bool
		wantError                   bool
		wantRequests                int64
	}{
		{name: "local-inspect", tool: "inspect"},
		{name: "local-audit", tool: "audit"},
		{name: "local-plan", tool: "plan"},
		{name: "no-host-inspect", tool: "inspect", remote: true, wantError: true},
		{name: "no-host-audit", tool: "audit", remote: true, wantError: true},
		{name: "no-host-plan", tool: "plan", remote: true, wantError: true},
		{name: "allowed-host-inspect", tool: "inspect", remote: true, allowHost: true, wantRequests: 1},
		{name: "allowed-host-audit", tool: "audit", remote: true, allowHost: true, wantRequests: 1},
		{name: "allowed-host-plan", tool: "plan", remote: true, allowHost: true, wantRequests: 1},
		// These canceled calls check the other entry-point preconditions without
		// executing discovery or an API operation, even on the previous code.
		{name: "no-host-discover-precondition", tool: "discover", canceled: true, wantError: true},
		{name: "no-host-active-scan-precondition", tool: "scan", canceled: true, wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{AllowedRoots: []string{root}, AllowPrivate: true, MaxRequests: 2, MaxBodyBytes: 1 << 20, Timeout: time.Second}
			if tc.allowHost {
				cfg.AllowedHosts = []string{"127.0.0.1"}
			}
			cfg.Active = tc.tool == "scan"
			service, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			policyBefore := service.policyJSON()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if tc.canceled {
				cancel()
			}
			source := local
			if tc.remote {
				source = server.URL + "/spec.json"
			}
			before := requests.Load()
			var operations []string
			switch tc.tool {
			case "inspect", "audit":
				out, callErr := service.inspect(ctx, source, tc.tool == "audit")
				operations, err = out.Endpoints, callErr
			case "plan":
				out, callErr := service.plan(ctx, source)
				err = callErr
				for _, request := range out.Requests {
					operations = append(operations, request.Method+" "+request.Path)
				}
			case "discover":
				_, err = service.discover(ctx, discoverArgs{Host: "127.0.0.1", Limit: 1})
			case "scan":
				_, err = service.runScan(ctx, source)
			}
			if tc.wantError {
				if err == nil || !strings.Contains(err.Error(), "--allow-host") || !strings.Contains(err.Error(), "startup") {
					t.Errorf("want missing startup-host error; got %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(operations, []string{"GET /a"}) {
					t.Errorf("operations = %v; want GET /a", operations)
				}
			}
			if got := requests.Load() - before; got != tc.wantRequests {
				t.Errorf("received %d HTTP requests; want %d", got, tc.wantRequests)
			}
			if service.policyJSON() != policyBefore {
				t.Error("startup policy changed during the call")
			}
		})
	}
}
