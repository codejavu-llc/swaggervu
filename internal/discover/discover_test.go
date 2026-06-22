package discover

import "testing"

func TestBaseURLs(t *testing.T) {
	// Bare host, mixed -> both schemes.
	got := baseURLs("example.com", true)
	if len(got) != 2 || got[0] != "https://example.com" || got[1] != "http://example.com" {
		t.Errorf("mixed bare host: got %v", got)
	}
	// Bare host, https-only.
	got = baseURLs("example.com", false)
	if len(got) != 1 || got[0] != "https://example.com" {
		t.Errorf("https-only bare host: got %v", got)
	}
	// Explicit scheme is honored regardless of mixed.
	got = baseURLs("http://example.com/", true)
	if len(got) != 1 || got[0] != "http://example.com" {
		t.Errorf("explicit scheme: got %v", got)
	}
}

func TestRandString(t *testing.T) {
	a, b := randString(21), randString(21)
	if len(a) != 21 {
		t.Fatalf("expected length 21, got %d", len(a))
	}
	if a == b {
		t.Error("two random strings should not collide")
	}
}
