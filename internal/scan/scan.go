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
	"github.com/codejavu-inc/swaggervu/internal/textutil"
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
	// AuthStatus is the status of the authenticated comparison request, set only
	// in auth-aware mode (Status then holds the unauthenticated status).
	AuthStatus int `json:"auth_status,omitempty"`
	// Reasons explains why a result was flagged (e.g. "unauthenticated data",
	// "broken access control", "stack trace"). Empty for uninteresting results.
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
	// AuthHeaders, when non-empty, enables auth-aware scanning: every endpoint is
	// probed twice (without and with these headers) to detect broken access
	// control — operations the spec says need auth that still return data
	// unauthenticated, and endpoints whose response ignores the token entirely.
	AuthHeaders map[string]string
	GenOpts     requestgen.Options
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
	authMode := len(cfg.AuthHeaders) > 0
	emit := func(res Result) {
		mu.Lock()
		out = append(out, res)
		mu.Unlock()
		if onResult != nil {
			onResult(res)
		}
	}
	httpclient.ForEach(ctx, cfg.Concurrency, reqs, func(ctx context.Context, req requestgen.Request) {
		headers := map[string]string{}
		for k, v := range req.Headers {
			headers[k] = v
		}
		if req.ContentType != "" {
			headers["Content-Type"] = req.ContentType
		}
		if authMode {
			probeAuthAware(ctx, client, req, headers, cfg, emit, onResult)
			return
		}
		resp, err := client.DoWithHeaders(ctx, req.Method, req.URL, bodyReader(req), headers)
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
		res.Reasons = reasonsFor(found, detectLeaks(body))
		if resp.Status == 200 && len(resp.Body) >= largeResponseBytes && !isHTMLShell(body) {
			res.Reasons = append(res.Reasons, "unauthenticated data")
		}
		res.Interesting = len(res.Reasons) > 0
		emit(res)
	})
	return out
}

// probeAuthAware fires an endpoint without and with the auth headers and
// classifies the access-control outcome. Findings are derived from the
// unauthenticated response (what an anonymous attacker sees); the authenticated
// response is used only to tell "token is ignored" apart from "genuinely public".
func probeAuthAware(ctx context.Context, client *httpclient.Client, req requestgen.Request, baseHeaders map[string]string, cfg Config, emit, onResult func(Result)) {
	unauth, err := client.DoWithHeaders(ctx, req.Method, req.URL, bodyReader(req), baseHeaders)
	if err != nil {
		return
	}
	authHeaders := map[string]string{}
	for k, v := range baseHeaders {
		authHeaders[k] = v
	}
	for k, v := range cfg.AuthHeaders {
		authHeaders[k] = v
	}
	var authStatus int
	var authBody string
	if authed, err := client.DoWithHeaders(ctx, req.Method, req.URL, bodyReader(req), authHeaders); err == nil {
		authStatus = authed.Status
		authBody = authed.BodyString()
	}

	body := unauth.BodyString()
	found := secrets.Scan(body)
	res := Result{
		Method:        req.Method,
		URL:           req.URL,
		Path:          req.Path,
		Status:        unauth.Status,
		AuthStatus:    authStatus,
		ContentLength: len(unauth.Body),
		Secrets:       found,
	}
	res.Reasons = reasonsFor(found, detectLeaks(body))
	res.Reasons = append(res.Reasons, accessControlReasons(req.RequiresAuth, unauth.Status, len(unauth.Body), body, authStatus, authBody)...)
	res.Interesting = len(res.Reasons) > 0
	if res.Interesting || cfg.EmitAll {
		if res.Interesting {
			emit(res)
		} else if onResult != nil {
			onResult(res)
		}
	}
}

// reasonsFor turns secret findings and leak signatures into reason strings.
func reasonsFor(found []secrets.Finding, leaks []string) []string {
	var rs []string
	for _, f := range found {
		rs = append(rs, "secret: "+f.Type)
	}
	return append(rs, leaks...)
}

// accessControlReasons classifies the access-control outcome of an auth-aware
// probe. It only fires when the unauthenticated request returned real data.
func accessControlReasons(requiresAuth bool, unauthStatus, unauthLen int, unauthBody string, authStatus int, authBody string) []string {
	if unauthStatus != 200 || unauthLen < largeResponseBytes || isHTMLShell(unauthBody) {
		return nil
	}
	switch {
	case requiresAuth:
		// The spec says this operation needs auth, yet an anonymous request got
		// data back — the strongest broken-access-control signal.
		return []string{"broken access control"}
	case authStatus == 200 && textutil.Similarity(unauthBody, authBody) > 0.9:
		// Authenticated and anonymous responses are near-identical — the token is
		// ignored, so access control is not actually enforced.
		return []string{"auth not enforced"}
	default:
		return []string{"unauthenticated data"}
	}
}

// bodyReader returns a fresh reader for a request body (nil when empty), so the
// same request can be sent more than once in auth-aware mode.
func bodyReader(req requestgen.Request) io.Reader {
	if req.Body == "" {
		return nil
	}
	return strings.NewReader(req.Body)
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
