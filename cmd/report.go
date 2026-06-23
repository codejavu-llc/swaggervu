package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/codejavu-llc/swaggervu/internal/scan"
	"github.com/codejavu-llc/swaggervu/internal/spec"
)

// severity maps a finding's reasons to a coarse severity used in reports.
func severityForReasons(reasons []string) string {
	high, medium := false, false
	for _, r := range reasons {
		switch {
		case strings.HasPrefix(r, "secret:"), r == "broken access control":
			high = true
		case r == "auth not enforced", r == "stack trace", r == "sql error",
			r == "go panic", r == ".NET error", r == "php error",
			r == "debug enabled", r == "unauthenticated data", r == "internal path":
			medium = true
		}
	}
	switch {
	case high:
		return "High"
	case medium:
		return "Medium"
	default:
		return "Info"
	}
}

// renderScanMarkdown produces a paste-ready Markdown report of scan findings.
func renderScanMarkdown(s *spec.Spec, src string, results []scan.Result) string {
	var b strings.Builder
	title := "API"
	if s != nil && s.Title != "" {
		title = s.Title
	}
	fmt.Fprintf(&b, "# SwaggerVu report — %s\n\n", title)
	fmt.Fprintf(&b, "- **Source:** `%s`\n", src)
	if s != nil {
		fmt.Fprintf(&b, "- **Spec:** %s\n", s.Kind)
	}
	fmt.Fprintf(&b, "- **Generated:** %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Findings:** %d\n\n", len(results))

	if len(results) == 0 {
		b.WriteString("_No unauthenticated data exposure or secret leaks detected._\n")
		return b.String()
	}

	for i, r := range results {
		sev := severityForReasons(r.Reasons)
		fmt.Fprintf(&b, "## %d. [%s] %s %s\n\n", i+1, sev, r.Method, r.Path)
		fmt.Fprintf(&b, "- **URL:** %s\n", r.URL)
		fmt.Fprintf(&b, "- **Status:** %d  ·  **Size:** %d bytes\n", r.Status, r.ContentLength)
		if len(r.Reasons) > 0 {
			fmt.Fprintf(&b, "- **Signals:** %s\n", strings.Join(r.Reasons, ", "))
		}
		for _, f := range r.Secrets {
			fmt.Fprintf(&b, "  - secret `%s`: `%s`\n", f.Type, f.Match)
		}
		b.WriteString("\n**Reproduce:**\n\n```bash\n")
		fmt.Fprintf(&b, "curl -sk -X %s '%s'\n", r.Method, r.URL)
		b.WriteString("```\n\n")
	}
	return b.String()
}

// renderAllMarkdown produces a paste-ready Markdown report of an autopilot run.
func renderAllMarkdown(r *allReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# SwaggerVu autopilot report\n\n")
	fmt.Fprintf(&b, "- **Targets:** %s\n", strings.Join(r.Domains, ", "))
	fmt.Fprintf(&b, "- **Generated:** %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Specs found:** %d  ·  **UI pages:** %d  ·  **Confirmed exploits:** %d\n\n",
		len(r.Specs), len(r.UIPages), countVuln(r.Exploits))

	for _, sp := range r.Specs {
		fmt.Fprintf(&b, "## %s\n\n", sp.Title)
		fmt.Fprintf(&b, "- **Spec:** `%s` (%s, %d endpoints)\n\n", sp.URL, sp.Kind, sp.Endpoints)
		if len(sp.Interesting) > 0 {
			b.WriteString("### Interesting endpoints\n\n")
			for _, r := range sp.Interesting {
				sev := severityForReasons(r.Reasons)
				fmt.Fprintf(&b, "- **[%s]** `%s %s` — %d bytes [%s]\n",
					sev, r.Method, r.URL, r.ContentLength, strings.Join(r.Reasons, ", "))
			}
			b.WriteString("\n")
		}
		if len(sp.Secrets) > 0 {
			b.WriteString("### Secrets in spec\n\n")
			for _, f := range sp.Secrets {
				fmt.Fprintf(&b, "- `%s`: `%s`\n", f.Type, f.Match)
			}
			b.WriteString("\n")
		}
	}

	if len(r.Exploits) > 0 {
		b.WriteString("## Confirmed client-side CVEs\n\n")
		for _, f := range r.Exploits {
			if !f.Vulnerable {
				continue
			}
			fmt.Fprintf(&b, "### [High] %s — %s\n\n", f.Type, f.CVE)
			fmt.Fprintf(&b, "- **Target:** %s\n", f.TargetURL)
			fmt.Fprintf(&b, "- **PoC URL:** %s\n", f.TestedURL)
			fmt.Fprintf(&b, "- **Signal:** %s\n", f.Signal)
			if f.Evidence != "" {
				fmt.Fprintf(&b, "- **Screenshot:** `%s`\n", f.Evidence)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}
