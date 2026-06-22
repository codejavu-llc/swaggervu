package secrets

import "testing"

func TestScanFindsKnownSecrets(t *testing.T) {
	body := `{
		"aws": "AKIAIOSFODNN7EXAMPLE",
		"gh": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		"jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"nothing": "just a normal string value"
	}`
	found := Scan(body)
	want := map[string]bool{"AWS Access Key ID": false, "GitHub Token (classic)": false, "JWT": false}
	for _, f := range found {
		if _, ok := want[f.Type]; ok {
			want[f.Type] = true
		}
	}
	for typ, seen := range want {
		if !seen {
			t.Errorf("expected to detect %q, but did not", typ)
		}
	}
}

func TestScanDedupes(t *testing.T) {
	body := "AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE"
	found := Scan(body)
	count := 0
	for _, f := range found {
		if f.Type == "AWS Access Key ID" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 deduped AWS finding, got %d", count)
	}
}

func TestScanCleanIsEmpty(t *testing.T) {
	if f := Scan(`{"name":"petstore","version":"1.0.0"}`); len(f) != 0 {
		t.Fatalf("expected no findings on clean input, got %v", f)
	}
}
