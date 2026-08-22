// Package redact provides the single output-boundary sanitizer used by the CLI,
// reports, and MCP. It never mutates URLs used for the actual request.
package redact

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/codejavu-llc/swaggervu/data"
)

var sensitiveName = regexp.MustCompile(`(?i)(auth|token|secret|pass(word)?|key|signature|credential|session|cookie|jwt)`)
var urlInText = regexp.MustCompile(`https?://[^\s"'<>]+`)

// URL replaces every query value and strips userinfo. Even innocently named
// parameters can contain examples, identifiers, or credentials from a spec.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[INVALID-URL]"
	}
	u.User = nil
	u.Fragment = ""
	u.RawFragment = ""
	u.Path = Text(u.Path)
	u.RawPath = ""
	q := u.Query()
	for key := range q {
		if sensitiveName.MatchString(key) {
			q.Set(key, "[REDACTED]")
		} else {
			q.Set(key, "[VALUE]")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Text removes values matching the bundled secret corpus from arbitrary labels,
// paths, titles, and messages before they cross an output boundary.
func Text(raw string) string {
	for _, pattern := range data.SecretPatterns() {
		raw = pattern.Re.ReplaceAllString(raw, "[REDACTED]")
	}
	return raw
}

// Message sanitizes URLs embedded in arbitrary diagnostic text, then removes
// secret-pattern matches from the remainder.
func Message(raw string) string {
	raw = urlInText.ReplaceAllStringFunc(raw, URL)
	return Text(raw)
}

// Header reports whether a header value must never appear in output.
func Header(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key":
		return true
	default:
		return sensitiveName.MatchString(name)
	}
}

// Headers returns a copy with sensitive values replaced.
func Headers(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		if Header(key) {
			value = "[REDACTED]"
		}
		out[key] = value
	}
	return out
}
