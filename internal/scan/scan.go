// Package scan audits a loaded spec by generating and firing one request per
// operation, flagging endpoints reachable without auth and leaking data
// (skip-401/403 + largest-response BOLA heuristic from intruder-io/autoswagger).
package scan

import (
	"context"
	"io"
	"net/url"
	"strings"
	"sync"

	"github.com/codejavu-inc/swaggervu/internal/httpclient"
	"github.com/codejavu-inc/swaggervu/internal/requestgen"
	"github.com/codejavu-inc/swaggervu/internal/secrets"
	"github.com/codejavu-inc/swaggervu/internal/spec"
)

// largeResponseBytes is the threshold above which a 200 is "interesting".
const largeResponseBytes = 256

// Result is the outcome of probing one generated request.
type Result struct {
	Method        string `json:"method"`
	URL           string `json:"url"`
	Path          string `json:"path"`
	Status        int    `json:"status"`
	ContentLength int    `json:"content_length"`
	Interesting   bool   `json:"interesting"`
	// Reasons explains why a result was flagged (e.g. "unauthenticated data",
	// "stack trace", "secret: AWS Access Key ID"). Empty for uninteresting results.
	Reasons []string          `json:"reasons,omitempty"`
	Secrets []secrets.Finding `json:"secrets,omitempty"`
}

// Config controls a scan.
type Config struct {
	Concurrency int
	IncludeRisk bool
	// EmitAll reports every probed request to onResult, including 401/403 (which
	// are otherwise skipped as "auth enforced"). It does not change which results
	// are flagged Interesting or counted by the basepath-fallback heuristic.
	EmitAll bool
	GenOpts requestgen.Options
}

// Run scans a spec and calls onResult for each probed endpoint.
func Run(ctx context.Context, client *httpclient.Client, s *spec.Spec, cfg Config, onResult func(Result)) []Result {
	cfg.GenOpts.IncludeRisk = cfg.IncludeRisk
	reqs := requestgen.Build(s, cfg.GenOpts)
	results := fire(ctx, client, reqs, cfg, onResult)

	// Basepath fallback: if almost everything is an identical 404, the spec's
	// declared basePath is likely wrong — retry against the host root. Skip it
	// when the host root is the base we already scanned, otherwise we'd re-fire
	// every request and emit duplicate results.
	if shouldFallback(results) {
		root := strings.TrimRight(hostRoot(s), "/")
		if root != "" && root != requestgen.ResolveBase(s, cfg.GenOpts) {
			cfg.GenOpts.BaseURL = root
			reqs2 := requestgen.Build(s, cfg.GenOpts)
			results = append(results, fire(ctx, client, reqs2, cfg, onResult)...)
		}
	}
	return results
}

func fire(ctx context.Context, client *httpclient.Client, reqs []requestgen.Request, cfg Config, onResult func(Result)) []Result {
	var mu sync.Mutex
	var out []Result
	httpclient.ForEach(ctx, cfg.Concurrency, reqs, func(ctx context.Context, req requestgen.Request) {
		headers := map[string]string{}
		for k, v := range req.Headers {
			headers[k] = v
		}
		if req.ContentType != "" {
			headers["Content-Type"] = req.ContentType
		}
		var reqBody io.Reader
		if req.Body != "" {
			reqBody = strings.NewReader(req.Body)
		}
		resp, err := client.DoWithHeaders(ctx, req.Method, req.URL, reqBody, headers)
		if err != nil {
			return
		}
		// Access-control signal: 401/403 means auth is enforced — not a finding.
		// Surface it in verbose mode, but keep it out of the results slice so the
		// basepath-fallback heuristic is unaffected.
		if resp.Status == 401 || resp.Status == 403 {
			if cfg.EmitAll && onResult != nil {
				onResult(Result{
					Method:        req.Method,
					URL:           req.URL,
					Path:          req.Path,
					Status:        resp.Status,
					ContentLength: len(resp.Body),
				})
			}
			return
		}
		body := resp.BodyString()
		found := secrets.Scan(body)
		leaks := detectLeaks(body)
		res := Result{
			Method:        req.Method,
			URL:           req.URL,
			Path:          req.Path,
			Status:        resp.Status,
			ContentLength: len(resp.Body),
			Secrets:       found,
		}
		// Interesting, in order of signal strength:
		//   - any leaked secret (any status)
		//   - server internals leaked: stack trace / SQL / framework error (any status)
		//   - a reachable 200 carrying real data — but not a generic HTML app shell,
		//     which is a common false positive for an SPA's catch-all route.
		for _, f := range found {
			res.Reasons = append(res.Reasons, "secret: "+f.Type)
		}
		res.Reasons = append(res.Reasons, leaks...)
		if resp.Status == 200 && len(resp.Body) >= largeResponseBytes && !isHTMLShell(body) {
			res.Reasons = append(res.Reasons, "unauthenticated data")
		}
		if len(res.Reasons) > 0 {
			res.Interesting = true
		}
		mu.Lock()
		out = append(out, res)
		mu.Unlock()
		if onResult != nil {
			onResult(res)
		}
	})
	return out
}

// leakSignatures are high-signal substrings that reveal server internals
// (stack traces, framework errors, SQL errors, filesystem paths). A match makes
// a response interesting regardless of status code — a 500 leaking a stack trace
// is a finding even though it carries no "data".
var leakSignatures = []struct{ reason, sub string }{
	{"stack trace", "Traceback (most recent call last)"},
	{"stack trace", "Exception in thread"},
	{"stack trace", "\n\tat java."},
	{"stack trace", ".java:"},
	{"go panic", "goroutine "},
	{"sql error", "You have an error in your SQL syntax"},
	{"sql error", "SQLSTATE["},
	{"sql error", "ORA-0"},
	{"sql error", "psql: error"},
	{"sql error", "Unclosed quotation mark"},
	{".NET error", "Unhandled exception"},
	{".NET error", "   at System."},
	{".NET error", "System.Web.HttpException"},
	{"php error", "Fatal error:"},
	{"php error", "<b>Warning</b>:"},
	{"internal path", "/var/www/"},
	{"internal path", "/usr/local/lib"},
	{"internal path", `C:\inetpub`},
	{"internal path", `C:\Windows\`},
	{"debug enabled", "DEBUG = True"},
	{"debug enabled", "Werkzeug Debugger"},
}

// detectLeaks returns the distinct reasons a body reveals server internals.
func detectLeaks(body string) []string {
	var out []string
	seen := map[string]bool{}
	for _, sig := range leakSignatures {
		if seen[sig.reason] {
			continue
		}
		if strings.Contains(body, sig.sub) {
			seen[sig.reason] = true
			out = append(out, sig.reason)
		}
	}
	return out
}

// isHTMLShell reports whether a body looks like a full HTML page (an SPA shell or
// docs page) rather than API data — a frequent false positive for a 200 catch-all.
func isHTMLShell(body string) bool {
	t := strings.TrimSpace(body)
	if len(t) > 512 {
		t = t[:512]
	}
	lower := strings.ToLower(t)
	return strings.HasPrefix(lower, "<!doctype html") ||
		strings.HasPrefix(lower, "<html") ||
		strings.Contains(lower, "<head>")
}

// shouldFallback reports whether >80% of results are identical-length 404s.
func shouldFallback(results []Result) bool {
	if len(results) < 5 {
		return false
	}
	counts := map[int]int{}
	notFound := 0
	for _, r := range results {
		if r.Status == 404 {
			notFound++
			counts[r.ContentLength]++
		}
	}
	if float64(notFound)/float64(len(results)) < 0.8 {
		return false
	}
	for _, c := range counts {
		if float64(c)/float64(len(results)) >= 0.8 {
			return true
		}
	}
	return false
}

func hostRoot(s *spec.Spec) string {
	if s.SourceURL == "" {
		return ""
	}
	u, err := url.Parse(s.SourceURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
