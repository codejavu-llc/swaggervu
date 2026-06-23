// Package osint performs passive discovery of public API definitions via the
// SwaggerHub spec-search API (technique from UndeadSec/SwaggerSpy).
package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/codejavu-llc/swaggervu/internal/httpclient"
)

// Spec is a public definition found on SwaggerHub.
type Spec struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

type apiResponse struct {
	TotalCount int `json:"totalCount"`
	APIs       []struct {
		Description string `json:"description"`
		Properties  []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"properties"`
	} `json:"apis"`
}

const pageLimit = 100

// Search queries SwaggerHub for public specs matching term, streaming each spec
// to onSpec as it is found. It stops after maxPages pages (0 = all available).
// TotalCount from the first page is returned so callers can report scope.
func Search(ctx context.Context, client *httpclient.Client, term string, maxPages int, onSpec func(Spec)) (int, error) {
	first, err := fetchPage(ctx, client, term, 0)
	if err != nil {
		return 0, err
	}
	for _, sp := range collect(first) {
		onSpec(sp)
	}
	pages := first.TotalCount / pageLimit
	if maxPages > 0 && pages > maxPages-1 {
		pages = maxPages - 1
	}
	for page := 1; page <= pages; page++ {
		select {
		case <-ctx.Done():
			return first.TotalCount, ctx.Err()
		default:
		}
		r, err := fetchPage(ctx, client, term, page)
		if err != nil {
			continue
		}
		for _, sp := range collect(r) {
			onSpec(sp)
		}
	}
	return first.TotalCount, nil
}

func fetchPage(ctx context.Context, client *httpclient.Client, term string, page int) (*apiResponse, error) {
	u := fmt.Sprintf(
		"https://app.swaggerhub.com/apiproxy/specs?sort=BEST_MATCH&order=DESC&query=%s&page=%d&limit=%d",
		url.QueryEscape(term), page, pageLimit,
	)
	resp, err := client.Get(ctx, u)
	if err != nil {
		return nil, err
	}
	var ar apiResponse
	if err := json.Unmarshal(resp.Body, &ar); err != nil {
		return nil, fmt.Errorf("parse swaggerhub response: %w", err)
	}
	return &ar, nil
}

func collect(r *apiResponse) []Spec {
	var out []Spec
	for _, a := range r.APIs {
		for _, p := range a.Properties {
			if p.URL != "" {
				out = append(out, Spec{URL: p.URL, Description: a.Description})
			}
		}
	}
	return out
}
