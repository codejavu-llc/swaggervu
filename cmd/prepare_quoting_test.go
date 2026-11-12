package cmd

import (
	"testing"

	"github.com/codejavu-llc/swaggervu/internal/requestgen"
)

func TestCommandForQuoting(t *testing.T) {
	// Expected shell words are written explicitly. These tests inspect text;
	// they never execute curl, sqlmap, or a generated shell command.
	bodies := []struct {
		name, body, quotedBody string
	}{
		{"ordinary body", `{"name":"Reilly"}`, `'{"name":"Reilly"}'`},
		{"straight apostrophe", `{"name":"O'Reilly"}`, `'{"name":"O'"'"'Reilly"}'`},
		{"spaces unicode and two apostrophes", `{"name":"O'Reilly's café"}`, `'{"name":"O'"'"'Reilly'"'"'s café"}'`},
		{"curly apostrophe control", `{"name":"O’Reilly"}`, `'{"name":"O’Reilly"}'`},
	}
	for _, tool := range []string{"curl", "sqlmap"} {
		for _, tc := range bodies {
			t.Run(tool+"/"+tc.name, func(t *testing.T) {
				r := requestgen.Request{
					Method:      "POST",
					URL:         "https://example.invalid/write",
					ContentType: "application/json",
					Body:        tc.body,
				}
				want := "curl --fail-with-body -sS -X POST 'https://example.invalid/write' -H 'Content-Type: application/json' --data " + tc.quotedBody
				if tool == "sqlmap" {
					want = "sqlmap -u 'https://example.invalid/write' --batch --method=POST --data=" + tc.quotedBody
				}
				if got := commandFor(tool, r); got != want {
					t.Fatalf("printed command = %q; want %q", got, want)
				}
			})
		}
	}
	for _, tc := range []struct {
		name, value, quotedHeader string
	}{
		{"ordinary header", "Book club", `'X-Book-Title: Book club'`},
		{"header apostrophe", "Reader's choice", `'X-Book-Title: Reader'"'"'s choice'`},
	} {
		t.Run("curl/"+tc.name, func(t *testing.T) {
			r := requestgen.Request{
				Method:  "GET",
				URL:     "https://example.invalid/read",
				Headers: map[string]string{"X-Book-Title": tc.value},
			}
			want := "curl --fail-with-body -sS -X GET 'https://example.invalid/read' -H " + tc.quotedHeader
			if got := commandFor("curl", r); got != want {
				t.Fatalf("printed command = %q; want %q", got, want)
			}
		})
	}
}
