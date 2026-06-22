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

	"github.com/codejavu-inc/swaggervu/data"
	"github.com/codejavu-inc/swaggervu/internal/httpclient"
	"github.com/codejavu-inc/swaggervu/internal/spec"
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
		if err == nil && r2.Status == 200 && similarity(baseline, r2.BodyString()) > 0.90 {
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
		body := resp.BodyString()
		// Reject responses too similar to the error baseline (false positive).
		if baselineStatus == 200 && similarity(body, baseline) > 0.90 {
			continue
		}
		h := Hit{Target: target, URL: u, Status: resp.Status}
		if k, v := spec.Detect(resp.Body); k != spec.KindUnknown {
			if s, err := spec.Load(resp.Body, u); err == nil && s.Doc != nil {
				h.IsSpec = true
				h.Kind = s.Kind
				h.Version = v
				h.Title = s.Title
			}
		}
		if h.IsSpec || data.LooksLikeSwagger(body) {
			h.Marker = data.MatchedMarker(body)
			emit(h)
			found = true
			if cfg.FirstOnly {
				return
			}
		}
	}
	_ = found
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

// similarity returns a Sørensen–Dice coefficient over character bigrams,
// a cheap stand-in for Python's difflib.SequenceMatcher ratio.
func similarity(a, b string) float64 {
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
