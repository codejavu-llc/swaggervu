// Package browser uses a headless Chromium instance to discover API definitions
// behind JavaScript-rendered docs UIs (ReDoc, RapiDoc, swagger-ui) by watching
// the network for the spec request the page makes after it loads.
package browser

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/codejavu-llc/swaggervu/internal/spec"
)

// specURLHint matches response URLs that plausibly carry an API definition.
var specURLHint = regexp.MustCompile(`(?i)(swagger|openapi|api-?docs?|/spec|definition|\.json|\.yaml|\.yml)`)

type respMeta struct {
	url      string
	mimeType string
	id       network.RequestID
}

// Result holds what the headless pass found.
type Result struct {
	Spec       *spec.Spec
	SpecURL    string
	Candidates []string // every spec-looking URL the page requested
}

// FindSpec loads pageURL in headless Chromium, captures network responses, and
// returns the first that parses as a Swagger/OpenAPI definition.
func FindSpec(ctx context.Context, pageURL string, insecure bool, wait time.Duration) (*Result, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)
	if insecure {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	tabCtx, tabCancel := chromedp.NewContext(allocCtx)
	defer tabCancel()
	if wait <= 0 {
		wait = 6 * time.Second
	}
	tabCtx, toCancel := context.WithTimeout(tabCtx, wait+20*time.Second)
	defer toCancel()

	var mu sync.Mutex
	var responses []respMeta
	chromedp.ListenTarget(tabCtx, func(ev any) {
		if e, ok := ev.(*network.EventResponseReceived); ok && e.Response != nil {
			mu.Lock()
			responses = append(responses, respMeta{
				url:      e.Response.URL,
				mimeType: e.Response.MimeType,
				id:       e.RequestID,
			})
			mu.Unlock()
		}
	})

	res := &Result{}
	err := chromedp.Run(tabCtx,
		network.Enable(),
		chromedp.Navigate(pageURL),
		chromedp.Sleep(wait),
		chromedp.ActionFunc(func(ctx context.Context) error {
			mu.Lock()
			snapshot := make([]respMeta, len(responses))
			copy(snapshot, responses)
			mu.Unlock()

			seen := map[string]bool{}
			for _, r := range snapshot {
				if !isCandidate(r) || seen[r.url] {
					continue
				}
				seen[r.url] = true
				res.Candidates = append(res.Candidates, r.url)

				// Pull the response body straight from the browser (preserves
				// the auth/headers the page used to fetch it).
				body, err := network.GetResponseBody(r.id).Do(ctx)
				if err != nil || len(body) == 0 {
					continue
				}
				if k, _ := spec.Detect(body); k == spec.KindUnknown {
					continue
				}
				if s, err := spec.Load(body, r.url); err == nil && s.Doc != nil {
					res.Spec = s
					res.SpecURL = r.url
					return nil // first valid spec wins
				}
			}
			return nil
		}),
	)
	if err != nil {
		return res, err
	}
	return res, nil
}

func isCandidate(r respMeta) bool {
	mt := strings.ToLower(r.mimeType)
	if strings.Contains(mt, "json") || strings.Contains(mt, "yaml") || strings.Contains(mt, "yml") {
		return true
	}
	return specURLHint.MatchString(r.url)
}
