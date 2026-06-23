package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codejavu-llc/swaggervu/data"
	"github.com/codejavu-llc/swaggervu/internal/discover"
	"github.com/codejavu-llc/swaggervu/internal/osint"
	"github.com/codejavu-llc/swaggervu/internal/output"
	"github.com/codejavu-llc/swaggervu/internal/wayback"
	"github.com/spf13/cobra"
)

var (
	discFile      string
	discMixed     bool
	discHTTPSOnly bool
	discWordlist  string
	discListPaths bool
	discFirstOnly bool
	discPathsOnly bool
	discNoDomain  bool
	discWayback   bool
	discOSINT     bool
	discOSINTPgs  int
)

var discoverCmd = &cobra.Command{
	Use:   "discover [targets...]",
	Short: "Find exposed Swagger/OpenAPI endpoints across many targets",
	Long: `Probe targets with the flagship wordlist and confirm hits via content
matchers + random-path false-positive suppression. Targets may be hostnames or
full URLs, supplied as args, with -l file, or piped on stdin.

Extra sources (off by default) seed additional candidate spec URLs, which are
probed directly: --wayback (archived URLs) and --osint (public SwaggerHub specs).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if discListPaths {
			for _, p := range data.PathsSorted() {
				fmt.Println(p)
			}
			return nil
		}
		log.Banner(version)

		targets, err := readTargets(discFile, args)
		if err != nil {
			return err
		}

		// Seed candidate spec/UI URLs from extra sources. These are already
		// specific URLs (not hosts), so they are direct-probed, not path-probed.
		var candidates []string
		if discWayback {
			candidates = append(candidates, harvestWayback(cmd.Context(), targets)...)
		}
		if discOSINT {
			candidates = append(candidates, harvestOSINT(cmd.Context(), targets)...)
		}
		if len(targets) == 0 && len(candidates) == 0 {
			return fmt.Errorf("no targets provided (use args, -l file, or stdin)")
		}

		client, err := buildClient(false)
		if err != nil {
			return err
		}
		sink, err := output.NewSink(flagOutput, flagJSON)
		if err != nil {
			return err
		}
		defer sink.Close()

		// Probe both http and https for bare hosts by default (convenience);
		// --https-only restricts to https for faster mass scans. A target given
		// with an explicit scheme is always probed only on that scheme.
		cfg := discover.Config{
			Concurrency: flagConcurrency,
			Mixed:       !discHTTPSOnly,
			FirstOnly:   discFirstOnly,
		}
		if discWordlist != "" {
			paths, err := loadLines(discWordlist)
			if err != nil {
				return err
			}
			cfg.Paths = paths
		}

		// Live progress on stderr: targets probed / total, hits, elapsed. The
		// engine calls Progress once per completed target; throttle redraws but
		// always draw the final (done==total) frame so it ends at 100%.
		var hits int64
		start := time.Now()
		var drawMu sync.Mutex
		var lastDraw time.Time
		cfg.Progress = func(done, total int) {
			drawMu.Lock()
			if done != total && time.Since(lastDraw) < 150*time.Millisecond {
				drawMu.Unlock()
				return
			}
			lastDraw = time.Now()
			drawMu.Unlock()
			log.Progress("probing %d/%d · %d hit(s) · %s",
				done, total, atomic.LoadInt64(&hits), time.Since(start).Round(time.Second))
		}
		defer log.ProgressDone() // safety net for early return / Ctrl-C

		emitHit := func(h discover.Hit) {
			atomic.AddInt64(&hits, 1)
			kind := string(h.Kind)
			if kind == "" {
				kind = "ui"
			}
			log.Good("%s  [%s] %s", h.URL, kind, h.Title)
			if flagJSON {
				sink.Add(h)
				return
			}
			if discPathsOnly {
				sink.WriteLine(formatPath(h.URL, discNoDomain))
			} else {
				sink.WriteLine(h.URL)
			}
		}

		// Path-probe bare hosts/URLs with the wordlist; direct-probe the
		// already-specific candidate URLs from Wayback/OSINT.
		if len(targets) > 0 {
			discover.Run(cmd.Context(), client, targets, cfg, emitHit)
		}
		if len(candidates) > 0 {
			discover.ProbeURLs(cmd.Context(), client, candidates, flagConcurrency, emitHit, cfg.Progress)
		}
		log.ProgressDone()
		log.Info("discovery complete: %d endpoint(s) found in %s",
			atomic.LoadInt64(&hits), time.Since(start).Round(time.Second))
		return nil
	},
}

// harvestOSINT collects public spec URLs from SwaggerHub for each target term.
func harvestOSINT(ctx context.Context, targets []string) []string {
	client, err := buildClient(true)
	if err != nil {
		return nil
	}
	var extra []string
	for _, t := range targets {
		n := 0
		if _, err := osint.Search(ctx, client, t, discOSINTPgs, func(sp osint.Spec) {
			extra = append(extra, sp.URL)
			n++
		}); err != nil {
			continue
		}
		log.Info("osint: %d SwaggerHub spec(s) for %s", n, t)
	}
	return extra
}

// harvestWayback pulls archived API URLs for each target domain.
func harvestWayback(ctx context.Context, targets []string) []string {
	client, err := buildClient(true)
	if err != nil {
		return nil
	}
	var extra []string
	for _, t := range targets {
		urls, err := wayback.Fetch(ctx, client, t)
		if err != nil {
			continue
		}
		log.Info("wayback: %d archived API URL(s) for %s", len(urls), t)
		extra = append(extra, urls...)
	}
	return extra
}

// formatPath returns the URL path with or without its domain prefix.
func formatPath(rawURL string, noDomain bool) string {
	if !noDomain {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	p := u.Path
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	if p == "" {
		p = "/"
	}
	return p
}

func loadLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, nil
}

func init() {
	f := discoverCmd.Flags()
	f.StringVarP(&discFile, "list", "l", "", "file of targets (one per line)")
	f.BoolVar(&discHTTPSOnly, "https-only", false, "probe https only (default: probe both http and https for bare hosts)")
	f.BoolVarP(&discMixed, "mixed", "m", true, "deprecated: both schemes are probed by default")
	_ = f.MarkDeprecated("mixed", "both http and https are probed by default; use --https-only to restrict to https")
	f.StringVarP(&discWordlist, "wordlist", "w", "", "custom path wordlist (overrides built-in)")
	f.BoolVar(&discListPaths, "list-paths", false, "print the built-in flagship wordlist and exit")
	f.BoolVar(&discFirstOnly, "first-only", false, "stop after the first hit per host")
	f.BoolVar(&discPathsOnly, "paths-only", false, "output only matched paths/URLs")
	f.BoolVar(&discNoDomain, "no-domain", false, "with --paths-only, strip the domain (path only)")
	f.BoolVar(&discWayback, "wayback", false, "also seed candidates from the Wayback Machine")
	f.BoolVar(&discOSINT, "osint", false, "also seed candidates from SwaggerHub (OSINT)")
	f.IntVar(&discOSINTPgs, "osint-pages", 5, "max SwaggerHub result pages for --osint (100/page; 0 = all)")
	rootCmd.AddCommand(discoverCmd)
}
