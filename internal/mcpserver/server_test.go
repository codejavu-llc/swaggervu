package mcpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRequiresExplicitScope(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected missing scope to fail")
	}
}

func TestAllowedFileAndInspect(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "openapi.json")
	body := []byte(`{"openapi":"3.0.0","info":{"title":"MCP Test","version":"1"},"paths":{"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{AllowedRoots: []string{root}, MaxBodyBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.inspect(context.Background(), path, true)
	if err != nil {
		t.Fatal(err)
	}
	if out.Title != "MCP Test" || len(out.Endpoints) != 1 {
		t.Fatalf("unexpected inspection: %#v", out)
	}
	if _, err := service.allowedFile(filepath.Join(root, "..", "outside.json")); err == nil {
		t.Fatal("expected path escape to fail")
	}
}

func TestAllowedFileRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "private.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	service, err := New(Config{AllowedRoots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.allowedFile(link); err == nil {
		t.Fatal("expected symlink escape to fail")
	}
}

func TestAllowedRootAuthorityDoesNotFollowRetargetedSymlink(t *testing.T) {
	parent := t.TempDir()
	first, second := t.TempDir(), t.TempDir()
	rootLink := filepath.Join(parent, "scope")
	if err := os.Symlink(first, rootLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	service, err := New(Config{AllowedRoots: []string{rootLink}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(rootLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, rootLink); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(second, "new.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.allowedFile(filepath.Join(rootLink, "new.json")); err == nil {
		t.Fatal("retargeting an allowed-root symlink expanded startup authority")
	}
}

func TestScanDisabledWithoutStartupActive(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "openapi.json")
	_ = os.WriteFile(path, []byte(`{"openapi":"3.0.0","info":{"title":"x","version":"1"},"paths":{}}`), 0o600)
	service, err := New(Config{AllowedRoots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.runScan(context.Background(), path); err == nil {
		t.Fatal("expected active scan to be denied")
	}
}

func TestActiveScanStoresSanitizedFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{" + strings.Repeat("x", 300) + "}"))
	}))
	defer server.Close()
	root := t.TempDir()
	path := filepath.Join(root, "openapi.json")
	body := fmt.Sprintf(`{"openapi":"3.0.3","info":{"title":"x","version":"1"},"servers":[{"url":%q}],"paths":{"/data":{"get":{"responses":{"200":{"description":"ok"}}}}}}`, server.URL)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{AllowedRoots: []string{root}, AllowedHosts: []string{"127.0.0.1"}, AllowPrivate: true, Active: true, MaxRequests: 10})
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.runScan(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 || out.Findings[0].Reasons[0] != "unauthenticated data" {
		t.Fatalf("unexpected active scan findings: %#v", out.Findings)
	}
}

func TestProtocolListsBoundedTools(t *testing.T) {
	ctx := context.Background()
	service, err := New(Config{AllowedRoots: []string{t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := service.Server().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "swaggervu-test", Version: "1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	listed, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 7 {
		t.Fatalf("got %d tools, want 7", len(listed.Tools))
	}
	for _, tool := range listed.Tools {
		if tool.Name == "run_readonly_scan" && tool.Annotations.ReadOnlyHint {
			t.Fatal("network scan must not claim to be read-only")
		}
	}
}
