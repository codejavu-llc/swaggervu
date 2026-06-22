package data

import (
	"strings"
	"testing"
)

// TestAllSecretPatternsCompile guards against shipping a regex that fails to
// compile (the init silently skips bad patterns, which would hide a typo).
func TestAllSecretPatternsCompile(t *testing.T) {
	if len(rawSecretPatterns) != len(compiledSecretPatterns) {
		t.Fatalf("pattern compile mismatch: %d raw vs %d compiled — a regex failed to compile",
			len(rawSecretPatterns), len(compiledSecretPatterns))
	}
}

// TestModernTokensMatch checks the newer prefixed-token patterns hit real-shaped samples.
func TestModernTokensMatch(t *testing.T) {
	samples := map[string]string{
		"GitLab Personal Access Token": "glpat-ABCDEFGHIJKLMNOPQRST",
		"Anthropic API Key":            "sk-ant-api03-AbCdEf012345_-AbCdEf012345",
		"SendGrid API Key":             "SG.AbCdEfGhIjKlMnOpQrStUv.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdEfG",
		"DigitalOcean Token":           "dop_v1_" + repeat("a", 64),
		"Postman API Key":              "PMAK-" + repeat("a", 24) + "-" + repeat("b", 34),
	}
	for _, p := range compiledSecretPatterns {
		if sample, ok := samples[p.Name]; ok {
			if !p.Re.MatchString(sample) {
				t.Errorf("pattern %q did not match sample %q", p.Name, sample)
			}
			delete(samples, p.Name)
		}
	}
	for name := range samples {
		t.Errorf("pattern %q not found in corpus", name)
	}
}

func repeat(s string, n int) string {
	return strings.Repeat(s, n)
}

func TestPathsDedupedAndPriorityFirst(t *testing.T) {
	all := Paths()
	seen := map[string]bool{}
	for _, p := range all {
		if seen[p] {
			t.Errorf("duplicate path in wordlist: %s", p)
		}
		seen[p] = true
	}
	if len(all) == 0 || all[0] != "/swagger.json" {
		t.Errorf("expected priority path first, got %v", all[0])
	}
}
