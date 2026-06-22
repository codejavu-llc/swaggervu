// Package wayback harvests a target's archived URLs from the Wayback Machine
// CDX API and filters them down to API/Swagger-looking endpoints.
package wayback

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/codejavu-inc/swaggervu/internal/httpclient"
)

// apiLike matches archived URLs worth testing for API definitions.
var apiLike = regexp.MustCompile(`(?i)(swagger|openapi|api-?docs?|/api/|/v[0-9]+/|\.json|\.yaml|\.yml|graphql|redoc|rapidoc)`)

// Fetch queries the CDX API for a domain and returns deduplicated, API-like URLs.
func Fetch(ctx context.Context, client *httpclient.Client, domain string) ([]string, error) {
	domain = cleanDomain(domain)
	cdx := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey&limit=50000",
		url.QueryEscape(domain),
	)
	resp, err := client.Get(ctx, cdx)
	if err != nil {
		return nil, err
	}
	// CDX json output is an array of [original] rows, first row is the header.
	var rows [][]string
	if err := json.Unmarshal(resp.Body, &rows); err != nil {
		return nil, fmt.Errorf("parse cdx response: %w", err)
	}
	seen := map[string]bool{}
	var out []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue // skip header
		}
		u := row[0]
		if !apiLike.MatchString(u) {
			continue
		}
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	sort.Strings(out)
	return out, nil
}

func cleanDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimSuffix(d, "/")
	if i := strings.IndexByte(d, '/'); i >= 0 {
		d = d[:i]
	}
	return d
}
