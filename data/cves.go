package data

// CVE describes a known Swagger/OpenAPI-tooling vulnerability and how SwaggerVu
// tests for it. PoCs are benign markers only — exploitation is opt-in and gated.
type CVE struct {
	ID          string
	Title       string
	Affected    string
	Description string
	// Param is the query parameter abused to load an attacker-controlled spec.
	Param string
	// Technique is a narrow identifier for the advisory's actual mechanism.
	Technique string
	Reference string
	// Testable is true only when the headless verifier has an independent,
	// scanner-owned assertion for this exact advisory.
	Testable bool
}

// Evaluated but intentionally NOT in the registry, because the headless engine
// (internal/exploit) confirms only configUrl/url DOM-XSS + spec-driven HTML
// injection, and these need a different confirmation path. Add them only
// alongside a real assertion — do not ship unverifiable coverage:
//   - CVE-2024-57083  ReDoc prototype pollution via mergeObjects() (fixed 2.4.0)
//   - RapiDoc / Stoplight Elements client-side issues — need a renderer-specific PoC

// SwaggerCVEs is the curated registry used by the exploit module, newest first.
// Every entry is verified against a primary source. Only entries marked Testable
// have a matching confirmation path in internal/exploit.
var SwaggerCVEs = []CVE{
	{
		ID:          "CVE-2025-8191",
		Title:       "macrozheng Mall Swagger UI configUrl XSS",
		Affected:    "macrozheng Mall 1.0.0 through 1.0.3",
		Description: "Application-specific configUrl XSS in macrozheng Mall's /swagger-ui/index.html integration. This is not a version-wide Swagger UI advisory.",
		Param:       "configUrl",
		Technique:   "application-specific-configUrl-xss",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2025-8191",
		Testable:    false,
	},
	{
		ID:          "CVE-2025-54432",
		Title:       "Swagger UI remote-spec reflected XSS chain",
		Affected:    "swagger-ui < 3.38.0 when the url option accepts remote definitions",
		Description: "A remote definition loaded through the url option can be combined with the historical DOMPurify bypass to create reflected XSS. Verification requires execution of SwaggerVu's tagged canary, not merely loading remote content.",
		Param:       "url",
		Technique:   "remote-spec-dompurify-xss",
		Reference:   "https://github.com/swagger-api/swagger-ui/security/advisories/GHSA-qrmm-w75w-3wpx",
		Testable:    true,
	},
	{
		ID:          "CVE-2018-25031",
		Title:       "Swagger UI remote-definition spoofing",
		Affected:    "swagger-ui <= 4.1.2; later/custom deployments may re-enable the option",
		Description: "The url option can display an attacker-controlled remote OpenAPI definition on a trusted documentation origin, enabling contextual spoofing or phishing. It is not, by itself, proof of XSS.",
		Param:       "url",
		Technique:   "remote-spec-spoofing",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2018-25031",
		Testable:    false,
	},
	{
		ID:          "CVE-2016-1000229",
		Title:       "swagger-ui index.html DOM XSS",
		Affected:    "swagger-ui 2.x",
		Description: "Historical Swagger UI XSS in spec key names. The current generic remote-description canary does not independently verify this technique.",
		Param:       "",
		Technique:   "spec-key-name-xss",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2016-1000229",
		Testable:    false,
	},
}

// InjectionParams returns the distinct query parameters worth testing, in order.
func InjectionParams() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range SwaggerCVEs {
		if c.Testable && c.Param != "" && !seen[c.Param] {
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
		if c.Testable && c.Param == param {
			out = append(out, c.ID)
		}
	}
	return out
}
