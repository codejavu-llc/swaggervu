// Package textutil provides small text-similarity helpers shared across modules
// (discovery false-positive baselining and authenticated-response diffing).
package textutil

// Similarity returns a Sørensen–Dice coefficient over character bigrams (0..1),
// a cheap stand-in for Python's difflib.SequenceMatcher ratio.
func Similarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) < 2 || len(b) < 2 {
		return 0
	}
	bigrams := func(s string) map[string]int {
		m := make(map[string]int, len(s))
		for i := 0; i < len(s)-1; i++ {
			m[s[i:i+2]]++
		}
		return m
	}
	ma, mb := bigrams(a), bigrams(b)
	inter := 0
	for bg, ca := range ma {
		if cb, ok := mb[bg]; ok {
			inter += min(ca, cb)
		}
	}
	return 2.0 * float64(inter) / float64((len(a)-1)+(len(b)-1))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
