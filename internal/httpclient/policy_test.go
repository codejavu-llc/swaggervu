package httpclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPrivateNetworkDeniedByDefault(t *testing.T) {
	c, err := New(DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), "http://127.0.0.1:8080/"); err == nil {
		t.Fatal("expected private target to be denied")
	}
}

func TestSpecialUseNetworksDenied(t *testing.T) {
	for _, raw := range []string{"192.0.2.1", "198.51.100.2", "203.0.113.3", "198.18.0.1", "100.64.0.1", "2001:db8::1"} {
		if !unsafeIP(net.ParseIP(raw)) {
			t.Errorf("special-use address was allowed: %s", raw)
		}
	}
	if unsafeIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("public unicast address was denied")
	}
}

func TestAllowedHostScopeIsExactAndNormalized(t *testing.T) {
	hosts, err := NormalizeAllowedHosts([]string{"API.Example.COM", "api.example.com"})
	if err != nil || len(hosts) != 1 || hosts[0] != "api.example.com" {
		t.Fatalf("unexpected normalized hosts: %#v, %v", hosts, err)
	}
	for _, raw := range []string{"https://api.example.com", "*.example.com", "api.example.com:443", "api.example.com/path"} {
		if _, err := NormalizeAllowedHosts([]string{raw}); err == nil {
			t.Errorf("expected ambiguous scope to fail: %q", raw)
		}
	}
}

func TestCredentialOriginsAreExact(t *testing.T) {
	origins, err := NormalizeCredentialOrigins([]string{"https://API.example.com/"})
	if err != nil || len(origins) != 1 || origins[0] != "https://api.example.com" {
		t.Fatalf("unexpected origin normalization: %#v, %v", origins, err)
	}
	for _, raw := range []string{"api.example.com", "https://user:pass@api.example.com", "https://api.example.com/path", "https://api.example.com?token=x"} {
		if _, err := NormalizeCredentialOrigins([]string{raw}); err == nil {
			t.Errorf("expected invalid origin to fail: %q", raw)
		}
	}
}

func TestSensitiveHeaderNames(t *testing.T) {
	for _, name := range []string{"Authorization", "X-Auth-Token", "Private-Token", "X-Amz-Security-Token", "X-API-Key", "Cookie"} {
		if !IsSensitiveHeader(name) {
			t.Errorf("sensitive header was not recognized: %s", name)
		}
	}
	if IsSensitiveHeader("Accept") {
		t.Fatal("ordinary header classified as sensitive")
	}
}

func TestRequestBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	opts := DefaultOptions()
	opts.AllowPrivate = true
	opts.MaxRequests = 1
	opts.Timeout = time.Second
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), srv.URL); !errors.Is(err, ErrRequestBudget) {
		t.Fatalf("got %v, want request budget error", err)
	}
}

func TestResponseBodyLimitReportsTruncation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("12345")) }))
	defer srv.Close()
	opts := DefaultOptions()
	opts.AllowPrivate = true
	opts.MaxBodyBytes = 4
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Truncated || string(resp.Body) != "1234" {
		t.Fatalf("unexpected capped response: %#v", resp)
	}
}

func TestSensitiveHeadersNeedBoundOrigin(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	defer srv.Close()
	opts := DefaultOptions()
	opts.AllowPrivate = true
	opts.Headers = map[string]string{"Authorization": "Bearer secret"}
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Get(context.Background(), srv.URL)
	if got != "" {
		t.Fatalf("credential leaked without bound origin: %q", got)
	}

	opts.CredentialOrigins = []string{srv.URL}
	c, _ = New(opts)
	_, _ = c.Get(context.Background(), srv.URL)
	if got != "Bearer secret" {
		t.Fatalf("bound credential missing: %q", got)
	}
}
