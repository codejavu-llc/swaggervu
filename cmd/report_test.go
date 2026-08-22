package cmd

import (
	"strings"
	"testing"

	"github.com/codejavu-llc/swaggervu/internal/scan"
	"github.com/codejavu-llc/swaggervu/internal/secrets"
	"github.com/codejavu-llc/swaggervu/internal/spec"
)

func TestSeverityForReasons(t *testing.T) {
	cases := []struct {
		reasons []string
		want    string
	}{
		{[]string{"secret: AWS Access Key ID"}, "High"},
		{[]string{"authorization differential"}, "Medium"},
		{[]string{"authentication invariant"}, "Medium"},
		{[]string{"stack trace"}, "Medium"},
		{[]string{"unauthenticated data"}, "Medium"},
		{[]string{"secret: x", "unauthenticated data"}, "High"},
		{[]string{"authorization differential", "authentication invariant"}, "Medium"},
		{nil, "Info"},
	}
	for _, c := range cases {
		if got := severityForReasons(c.reasons); got != c.want {
			t.Errorf("reasons %v: want %s, got %s", c.reasons, c.want, got)
		}
	}
}

func TestRenderScanMarkdown(t *testing.T) {
	s := &spec.Spec{Title: "Petstore", Kind: spec.KindSwagger2}
	results := []scan.Result{
		{
			Method: "GET", URL: "https://api.example.com/users", Path: "/users",
			Status: 200, ContentLength: 4096, Interesting: true,
			Reasons: []string{"unauthenticated data", "secret: JWT"},
			Secrets: []secrets.Finding{{Type: "JWT", Match: "[REDACTED]", Fingerprint: "hmac-sha256:1234", Length: 42}},
		},
	}
	md := renderScanMarkdown(s, "https://api.example.com/swagger.json", results)
	for _, want := range []string{"# SwaggerVu report — Petstore", "GET /users", "[High]", "curl --fail-with-body -sS -X GET", "secret `JWT`"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, md)
		}
	}
}

func TestRenderScanMarkdownEmpty(t *testing.T) {
	md := renderScanMarkdown(&spec.Spec{Title: "X"}, "src", nil)
	if !strings.Contains(md, "No configured evidence signals") {
		t.Errorf("expected empty-state message, got:\n%s", md)
	}
}
