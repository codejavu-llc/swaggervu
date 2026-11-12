// Package browser uses a headless Chromium instance to discover API definitions
// behind JavaScript-rendered docs UIs (ReDoc, RapiDoc, swagger-ui) by watching
// the network for the spec request the page makes after it loads.
package browser

import (
	"context"
	"os"
	"regexp"
	"strings"
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
	)
	if os.Geteuid() == 0 {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
	}
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

	res := &Result{}
	if _, err := chromedp.Call(tabCtx, network.Enable, network.EnableParams{}); err != nil {
		return res, err
	}

	captureCtx, stopCapture := context.WithCancel(tabCtx)
	events := chromedp.Events(captureCtx, network.ResponseReceived)
	var responses []respMeta
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e, err := range events {
			if err != nil {
				return
			}
			if e.Response == nil {
				continue
			}
			responses = append(responses, respMeta{
				url:      e.Response.URL,
				mimeType: e.Response.MimeType,
				id:       e.RequestID,
			})
		}
	}()

	err := chromedp.Do(tabCtx,
		chromedp.Navigate(pageURL),
		chromedp.Sleep(wait),
	)
	stopCapture()
	<-done
	if err != nil {
		return res, err
	}
	seen := map[string]bool{}
	for _, r := range responses {
		if !isCandidate(r) || seen[r.url] {
			continue
		}
		seen[r.url] = true
		res.Candidates = append(res.Candidates, r.url)

		// Pull the response body straight from the browser (preserves
		// the auth/headers the page used to fetch it).
		body, err := chromedp.Call(tabCtx, network.GetResponseBody, network.GetResponseBodyParams{RequestID: r.id})
		if err != nil || len(body.Body) == 0 {
			continue
		}
		if k, _ := spec.Detect(body.Body); k == spec.KindUnknown {
			continue
		}
		if s, err := spec.Load(body.Body, r.url); err == nil && s.Doc != nil {
			res.Spec = s
			res.SpecURL = r.url
			return res, nil // first valid spec wins
		}
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
