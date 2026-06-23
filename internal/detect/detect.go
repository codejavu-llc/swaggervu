// Package detect identifies whether a URL/response exposes a Swagger/OpenAPI
// definition and, if so, loads it into a normalized spec.
package detect

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/codejavu-llc/swaggervu/data"
	"github.com/codejavu-llc/swaggervu/internal/httpclient"
	"github.com/codejavu-llc/swaggervu/internal/spec"
)

// Result is the outcome of fingerprinting a single URL.
type Result struct {
	URL      string     `json:"url"`
	IsSpec   bool       `json:"is_spec"`             // parsed as a real definition
	IsUI     bool       `json:"is_ui"`               // swagger-ui/redoc HTML page
	Marker   string     `json:"marker,omitempty"`    // matched content marker
	Kind     spec.Kind  `json:"kind,omitempty"`      // version family
	Version  string     `json:"version,omitempty"`   // raw version
	Title    string     `json:"title,omitempty"`     // API title
	SpecURLs []string   `json:"spec_urls,omitempty"` // definition URLs extracted from a UI page
	Spec     *spec.Spec `json:"-"`
	Status   int        `json:"status"`
}

// specURLRe pulls definition URLs out of swagger-ui HTML/JS.
var specURLRe = regexp.MustCompile(`(?:url|configUrl|defaultDefinitionUrl|definitionURL)\s*[:=]\s*["']([^"']+)["']`)

// Inspect fetches a URL and decides whether it is a spec, a UI page, or neither.
func Inspect(ctx context.Context, client *httpclient.Client, target string) (*Result, error) {
	resp, err := client.Get(ctx, target)
	if err != nil {
		return nil, err
	}
	r := &Result{URL: target, Status: resp.Status}
	if resp.Status != 200 {
		return r, nil
	}
	body := resp.BodyString()

	// First, attempt to parse it directly as a definition.
	if k, _ := spec.Detect(resp.Body); k != spec.KindUnknown {
		if s, err := spec.Load(resp.Body, target); err == nil && s.Doc != nil {
			r.IsSpec = true
			r.Kind = s.Kind
			r.Version = s.Version
			r.Title = s.Title
			r.Spec = s
			r.Marker = data.MatchedMarker(body)
			return r, nil
		}
	}

	// Otherwise, check whether it's a UI page and try to extract the spec URL.
	if data.LooksLikeSwagger(body) {
		r.IsUI = true
		r.Marker = data.MatchedMarker(body)
		r.SpecURLs = extractSpecURLs(body, target)
	}
	return r, nil
}

// extractSpecURLs finds candidate definition URLs referenced by a UI page and
// resolves them against the page URL.
func extractSpecURLs(body, pageURL string) []string {
	seen := map[string]bool{}
	var out []string
	base, _ := url.Parse(pageURL)
	for _, m := range specURLRe.FindAllStringSubmatch(body, -1) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(raw, "data:") {
			continue
		}
		resolved := raw
		if base != nil {
			if ref, err := url.Parse(raw); err == nil {
				resolved = base.ResolveReference(ref).String()
			}
		}
		if !seen[resolved] {
			seen[resolved] = true
			out = append(out, resolved)
		}
	}
	sort.Strings(out)
	return out
}

// Endpoints returns "METHOD path" lines for a loaded spec, sorted.
func Endpoints(s *spec.Spec) []string {
	if s == nil || s.Doc == nil || s.Doc.Paths == nil {
		return nil
	}
	var out []string
	for path, item := range s.Doc.Paths.Map() {
		if item == nil {
			continue
		}
		for method := range item.Operations() {
			out = append(out, method+" "+path)
		}
	}
	sort.Strings(out)
	return out
}
