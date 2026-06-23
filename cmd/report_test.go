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
		{[]string{"broken access control"}, "High"},
		{[]string{"auth not enforced"}, "Medium"},
		{[]string{"stack trace"}, "Medium"},
		{[]string{"unauthenticated data"}, "Medium"},
		{[]string{"secret: x", "unauthenticated data"}, "High"},
		{[]string{"broken access control", "auth not enforced"}, "High"},
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
			Secrets: []secrets.Finding{{Type: "JWT", Match: "eyJ..."}},
		},
	}
	md := renderScanMarkdown(s, "https://api.example.com/swagger.json", results)
	for _, want := range []string{"# SwaggerVu report — Petstore", "GET /users", "[High]", "curl -sk -X GET", "secret `JWT`"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, md)
		}
	}
}

func TestRenderScanMarkdownEmpty(t *testing.T) {
	md := renderScanMarkdown(&spec.Spec{Title: "X"}, "src", nil)
	if !strings.Contains(md, "No unauthenticated data exposure") {
		t.Errorf("expected empty-state message, got:\n%s", md)
	}
}
