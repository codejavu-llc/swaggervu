// Package secrets scans text (spec bodies, API responses) for leaked
// credentials using the merged TruffleHog/SwaggerSpy regex corpus.
package secrets

import (
	"github.com/codejavu-llc/swaggervu/data"
)

// Finding is a single secret match.
type Finding struct {
	Type  string `json:"type"`
	Match string `json:"match"`
}

// Scan returns all secret findings in the given text. Matches are de-duplicated
// per (type, value) and truncated to avoid dumping huge blobs.
func Scan(text string) []Finding {
	if text == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []Finding
	for _, p := range data.SecretPatterns() {
		matches := p.Re.FindAllString(text, -1)
		for _, m := range matches {
			if len(m) > 120 {
				m = m[:120] + "…"
			}
			key := p.Name + "|" + m
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Finding{Type: p.Name, Match: m})
		}
	}
	return out
}

// Has reports whether any secret is present (cheap path).
func Has(text string) bool {
	for _, p := range data.SecretPatterns() {
		if p.Re.MatchString(text) {
			return true
		}
	}
	return false
}
