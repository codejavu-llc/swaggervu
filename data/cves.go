package data

import (
	"os"
	"strings"
)

// CVE describes a known Swagger/OpenAPI-tooling vulnerability and how SwaggerVu
// tests for it. PoCs are benign markers only — exploitation is opt-in and gated.
type CVE struct {
	ID          string
	Title       string
	Affected    string
	Description string
	// Param is the query parameter abused to load an attacker-controlled spec.
	Param string
	// Technique: "configUrl-xss" | "url-xss" | "html-injection".
	Technique string
	Reference string
}

// builtinDefaultPayloads are the hosted PoC specs injected by default for each
// injection param. Override per param with SWAGGERVU_PAYLOAD_<PARAM>, pass
// --payload PARAM=URL, or force the self-contained local PoC with
// `exploit --builtin-payload`.
var builtinDefaultPayloads = map[string]string{
	"configUrl": "https://jumpy-floor.surge.sh/test.json",
	"url":       "https://jumpy-floor.surge.sh/test.yaml",
}

// DefaultPayload returns the per-parameter PoC URL to inject. It prefers an
// environment override (SWAGGERVU_PAYLOAD_<PARAM>, param upper-cased, e.g.
// SWAGGERVU_PAYLOAD_CONFIGURL / SWAGGERVU_PAYLOAD_URL); when unset it falls back
// to the bundled default for that param. An empty result lets the exploit module
// use its local benign built-in PoC.
func DefaultPayload(param string) string {
	if v := os.Getenv("SWAGGERVU_PAYLOAD_" + strings.ToUpper(param)); v != "" {
		return v
	}
	return builtinDefaultPayloads[param]
}

// Evaluated but intentionally NOT in the registry, because the headless engine
// (internal/exploit) confirms only configUrl/url DOM-XSS + spec-driven HTML
// injection, and these need a different confirmation path. Add them only
// alongside a real assertion — do not ship unverifiable coverage:
//   - CVE-2024-57083  ReDoc prototype pollution via mergeObjects() (fixed 2.4.0)
//   - RapiDoc / Stoplight Elements client-side issues — need a renderer-specific PoC

// SwaggerCVEs is the curated registry used by the exploit module, newest first.
// Every entry is verified against a primary source (NVD or a vendor/GHSA advisory)
// and has a matching confirmation path in internal/exploit.
var SwaggerCVEs = []CVE{
	{
		ID:          "CVE-2025-8191",
		Title:       "Swagger UI DOM XSS via configUrl/url (DOMPurify bypass)",
		Affected:    "swagger-ui >= 3.14.1 and < 3.38.0 (fixed in 3.38.1)",
		Description: "Swagger UI renders the spec's description/markdown via React dangerouslySetInnerHTML after an outdated DOMPurify (<=2.2.2). A nested math/svg/textarea payload bypasses the sanitizer and executes JS. Loaded through the configUrl or url query parameter, so an attacker only needs a victim to open a crafted link.",
		Param:       "configUrl",
		Technique:   "dompurify-bypass-xss",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2025-8191",
	},
	{
		ID:          "CVE-2025-8191-url",
		Title:       "Swagger UI DOM XSS via url param (DOMPurify bypass)",
		Affected:    "swagger-ui >= 3.14.1 and < 3.38.0 (fixed in 3.38.1)",
		Description: "Same DOMPurify-bypass DOM XSS as CVE-2025-8191, delivered through the url query parameter instead of configUrl.",
		Param:       "url",
		Technique:   "dompurify-bypass-xss",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2025-8191",
	},
	{
		ID:          "CVE-2018-25031",
		Title:       "Swagger UI relative/remote spec DOM XSS via configUrl/url",
		Affected:    "swagger-ui < 3.23.11 (and forks accepting configUrl/url)",
		Description: "Swagger UI loads an externally supplied OpenAPI definition through the configUrl or url query parameter; a malicious spec can inject script/HTML into the rendered DOM.",
		Param:       "configUrl",
		Technique:   "configUrl-xss",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2018-25031",
	},
	{
		ID:          "CVE-2016-1000229",
		Title:       "swagger-ui index.html DOM XSS",
		Affected:    "swagger-ui 2.x",
		Description: "Reflected/DOM XSS in older swagger-ui where spec-controlled values are rendered without sanitization.",
		Param:       "url",
		Technique:   "url-xss",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2016-1000229",
	},
	{
		ID:          "GENERIC-SPEC-HTML-INJECTION",
		Title:       "Spec-driven HTML/markup injection in API documentation renderers",
		Affected:    "Swagger UI / ReDoc / RapiDoc rendering untrusted description/markdown fields",
		Description: "Description, title, and markdown fields from a remote spec are rendered into the docs page; unsanitized HTML in those fields leads to HTML injection or stored XSS.",
		Param:       "configUrl",
		Technique:   "html-injection",
		Reference:   "https://owasp.org/www-community/attacks/xss/",
	},
}

// InjectionParams returns the distinct query parameters worth testing, in order.
func InjectionParams() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range SwaggerCVEs {
		if !seen[c.Param] {
			seen[c.Param] = true
			out = append(out, c.Param)
		}
	}
	return out
}

// CVEsForParam returns the IDs of every registry entry that uses the given param.
func CVEsForParam(param string) []string {
	var out []string
	for _, c := range SwaggerCVEs {
		if c.Param == param {
			out = append(out, c.ID)
		}
	}
	return out
}
