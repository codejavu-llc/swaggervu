// Package secrets scans text (spec bodies, API responses) for leaked
// credentials using the merged TruffleHog/SwaggerSpy regex corpus.
package secrets

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/codejavu-llc/swaggervu/data"
)

// Finding is a single secret match.
type Finding struct {
	Type        string `json:"type"`
	Match       string `json:"match,omitempty"` // retained for v1 compatibility; always redacted
	Fingerprint string `json:"fingerprint"`
	Length      int    `json:"length"`
}

var (
	fingerprintOnce sync.Once
	fingerprintKey  [32]byte
)

func processFingerprintKey() []byte {
	fingerprintOnce.Do(func() {
		if _, err := rand.Read(fingerprintKey[:]); err != nil {
			fingerprintKey = sha256.Sum256([]byte("swaggervu-redaction-fallback"))
		}
	})
	return fingerprintKey[:]
}

func fingerprint(kind, value string) string {
	h := hmac.New(sha256.New, processFingerprintKey())
	_, _ = h.Write([]byte(kind))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(value))
	return "hmac-sha256:" + hex.EncodeToString(h.Sum(nil)[:8])
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
			key := p.Name + "|" + m
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Finding{
				Type:        p.Name,
				Match:       "[REDACTED]",
				Fingerprint: fingerprint(p.Name, m),
				Length:      len(m),
			})
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
