package scan

import "testing"

func TestDetectLeaks(t *testing.T) {
	cases := map[string]string{
		"Traceback (most recent call last):\n  File x":         "stack trace",
		"You have an error in your SQL syntax near":            "sql error",
		"panic: runtime error\ngoroutine 1 [running]:":         "go panic",
		"<b>Fatal error:</b> Uncaught Error in /var/www/x.php": "php error",
		"normal healthy json {\"ok\":true}":                    "",
	}
	for body, want := range cases {
		got := detectLeaks(body)
		if want == "" {
			if len(got) != 0 {
				t.Errorf("body %q: expected no leaks, got %v", body, got)
			}
			continue
		}
		found := false
		for _, r := range got {
			if r == want {
				found = true
			}
		}
		if !found {
			t.Errorf("body %q: expected reason %q, got %v", body, want, got)
		}
	}
}

func TestDetectLeaksNoFalsePositives(t *testing.T) {
	// Benign bodies that contain trigger-adjacent substrings must NOT flag.
	benign := []string{
		`{"type":"System.String","value":"ok"}`, // .NET type name in a spec, not an error
		`{"description":"returns a System.Collections list"}`,
		`{"note":"see at System level for details"}`,
		`{"warning":"low stock","items":[]}`, // "warning" but not a PHP error
	}
	for _, b := range benign {
		if got := detectLeaks(b); len(got) != 0 {
			t.Errorf("benign body %q falsely flagged: %v", b, got)
		}
	}
}

func TestDetectLeaksDedupes(t *testing.T) {
	body := "Traceback (most recent call last):\nException in thread main"
	got := detectLeaks(body)
	count := 0
	for _, r := range got {
		if r == "stack trace" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected one deduped 'stack trace' reason, got %d (%v)", count, got)
	}
}

func TestIsHTMLShell(t *testing.T) {
	if !isHTMLShell("<!DOCTYPE html><html><head><title>App</title></head>") {
		t.Error("expected HTML doctype to be detected as a shell")
	}
	if !isHTMLShell("  <html lang=\"en\">") {
		t.Error("expected leading-whitespace <html> to be detected")
	}
	if isHTMLShell(`{"users":[{"id":1,"name":"a"}]}`) {
		t.Error("JSON body should not be an HTML shell")
	}
}
