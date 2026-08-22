package redact

import (
	"strings"
	"testing"
)

func TestURL(t *testing.T) {
	raw := "https://user:pass@example.com/items?id=42&access_token=supersecret"
	got := URL(raw)
	if strings.Contains(got, "user") || strings.Contains(got, "pass") || strings.Contains(got, "supersecret") {
		t.Fatalf("sensitive URL data leaked: %s", got)
	}
	if strings.Contains(got, "id=42") || !strings.Contains(got, "%5BVALUE%5D") || !strings.Contains(got, "%5BREDACTED%5D") {
		t.Fatalf("unexpected sanitized URL: %s", got)
	}
}

func TestHeaders(t *testing.T) {
	got := Headers(map[string]string{"Authorization": "Bearer x", "Accept": "application/json"})
	if got["Authorization"] != "[REDACTED]" || got["Accept"] != "application/json" {
		t.Fatalf("unexpected headers: %#v", got)
	}
}

func TestText(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	if got := Text("title " + secret); strings.Contains(got, secret) {
		t.Fatalf("secret survived text redaction: %q", got)
	}
}

func TestMessageRedactsEmbeddedURL(t *testing.T) {
	got := Message("request https://example.com/a?id=42&token=supersecret failed")
	if strings.Contains(got, "42") || strings.Contains(got, "supersecret") {
		t.Fatalf("URL value survived message redaction: %q", got)
	}
}

func FuzzURLNeverReturnsCredentials(f *testing.F) {
	f.Add("https://user:pass@example.com/a?token=secret&id=42")
	f.Fuzz(func(t *testing.T, raw string) {
		got := URL(raw)
		if strings.Contains(got, "user:pass@") || strings.Contains(got, "token=secret") {
			t.Fatalf("credential survived redaction: %q", got)
		}
	})
}
