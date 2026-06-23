// Package discover actively probes targets for exposed Swagger/OpenAPI endpoints
// using the flagship wordlist, content matchers, and random-path false-positive
// suppression (technique from brinhosa/apidetector).
package discover

import (
	"context"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/codejavu-llc/swaggervu/data"
	"github.com/codejavu-llc/swaggervu/internal/httpclient"
	"github.com/codejavu-llc/swaggervu/internal/spec"
	"github.com/codejavu-llc/swaggervu/internal/textutil"
)

// Hit is a confirmed discovery.
type Hit struct {
	Target  string    `json:"target"`
	URL     string    `json:"url"`
	Status  int       `json:"status"`
	IsSpec  bool      `json:"is_spec"`
	Kind    spec.Kind `json:"kind,omitempty"`
	Version string    `json:"version,omitempty"`
	Title   string    `json:"title,omitempty"`
	Marker  string    `json:"marker,omitempty"`
}

// Config controls a discovery run.
type Config struct {
	Concurrency int
	Mixed       bool     // try http and https
	Paths       []string // override wordlist
	FirstOnly   bool     // stop after first hit per host
	// Progress, if set, is called once per target after it is fully probed,
	// with the number of targets completed so far and the total. Safe to call
	// from multiple goroutines (callers should keep it cheap / lock if needed).
	Progress func(done, total int)
}

// ProbeURLs direct-probes a set of candidate spec/UI URLs (e.g. harvested from
// the Wayback Machine or SwaggerHub OSINT), invoking onHit for each confirmed
// Swagger/OpenAPI resource. Unlike Run, it GETs each URL exactly as given rather
// than appending the wordlist — these are already specific URLs, not hosts.
// Progress, if set, is called once per URL completed.
func ProbeURLs(ctx context.Context, client *httpclient.Client, urls []string, concurrency int, onHit func(Hit), progress func(done, total int)) {
	var mu sync.Mutex
	emit := func(h Hit) {
		mu.Lock()
		defer mu.Unlock()
		onHit(h)
	}
	total := len(urls)
	var done int64
	httpclient.ForEach(ctx, concurrency, urls, func(ctx context.Context, u string) {
		probeExact(ctx, client, u, emit)
		if progress != nil {
			progress(int(atomic.AddInt64(&done, 1)), total)
		}
	})
}

// Run probes all targets and invokes onHit for each confirmed endpoint.
func Run(ctx context.Context, client *httpclient.Client, targets []string, cfg Config, onHit func(Hit)) {
	paths := cfg.Paths
	if len(paths) == 0 {
		paths = data.Paths()
	}
	var mu sync.Mutex
	emit := func(h Hit) {
		mu.Lock()
		defer mu.Unlock()
		onHit(h)
	}

	total := len(targets)
	var done int64
	httpclient.ForEach(ctx, cfg.Concurrency, targets, func(ctx context.Context, target string) {
		for _, base := range baseURLs(target, cfg.Mixed) {
			probeBase(ctx, client, base, target, paths, cfg, emit)
		}
		if cfg.Progress != nil {
			cfg.Progress(int(atomic.AddInt64(&done, 1)), total)
		}
	})
}

// probeBase establishes a per-host error baseline then probes each path.
func probeBase(ctx context.Context, client *httpclient.Client, base, target string, paths []string, cfg Config, emit func(Hit)) {
	// Baseline: request a random path to learn the "not found" response.
	randResp, err := client.Get(ctx, base+"/"+randString(21))
	if err != nil {
		return // host unreachable on this scheme
	}
	baseline := randResp.BodyString()
	baselineStatus := randResp.Status

	// Catch-all filter: if the host returns 200 to junk and a second random
	// junk path looks near-identical, it answers 200 for everything — skip.
	if baselineStatus == 200 {
		r2, err := client.Get(ctx, base+"/"+randString(21))
		if err == nil && r2.Status == 200 && textutil.Similarity(baseline, r2.BodyString()) > 0.90 {
			return
		}
	}

	found := false
	for _, p := range paths {
		select {
		case <-ctx.Done():
			return
		default:
		}
		u := base + p
		resp, err := client.Get(ctx, u)
		if err != nil || resp.Status != 200 {
			continue
		}
		// Reject responses too similar to the error baseline (false positive).
		if baselineStatus == 200 && textutil.Similarity(resp.BodyString(), baseline) > 0.90 {
			continue
		}
		if h, ok := classify(target, u, resp); ok {
			emit(h)
			found = true
			if cfg.FirstOnly {
				return
			}
		}
	}
	_ = found
}

// probeExact GETs a single candidate URL exactly as given (no wordlist) and
// emits it if it is a Swagger/OpenAPI resource. Used for full URLs from the
// Wayback Machine or OSINT sources.
func probeExact(ctx context.Context, client *httpclient.Client, rawURL string, emit func(Hit)) {
	resp, err := client.Get(ctx, rawURL)
	if err != nil || resp.Status != 200 {
		return
	}
	if h, ok := classify(rawURL, rawURL, resp); ok {
		emit(h)
	}
}

// classify builds a Hit from a 200 response and reports whether it is a
// confirmed (parsed) or likely (marker-matched) Swagger/OpenAPI resource.
func classify(target, url string, resp *httpclient.Response) (Hit, bool) {
	body := resp.BodyString()
	h := Hit{Target: target, URL: url, Status: resp.Status}
	if k, v := spec.Detect(resp.Body); k != spec.KindUnknown {
		if s, err := spec.Load(resp.Body, url); err == nil && s.Doc != nil {
			h.IsSpec = true
			h.Kind = s.Kind
			h.Version = v
			h.Title = s.Title
		}
	}
	if h.IsSpec || data.LooksLikeSwagger(body) {
		h.Marker = data.MatchedMarker(body)
		return h, true
	}
	return Hit{}, false
}

func baseURLs(target string, mixed bool) []string {
	target = strings.TrimRight(strings.TrimSpace(target), "/")
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return []string{target}
	}
	if mixed {
		return []string{"https://" + target, "http://" + target}
	}
	return []string{"https://" + target}
}

const charset = "abcdefghijklmnopqrstuvwxyz0123456789"

func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
