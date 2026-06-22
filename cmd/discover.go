package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/codejavu-inc/swaggervu/data"
	"github.com/codejavu-inc/swaggervu/internal/discover"
	"github.com/codejavu-inc/swaggervu/internal/output"
	"github.com/codejavu-inc/swaggervu/internal/wayback"
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
)

var discoverCmd = &cobra.Command{
	Use:   "discover [targets...]",
	Short: "Find exposed Swagger/OpenAPI endpoints across many targets",
	Long: `Probe targets with the flagship wordlist and confirm hits via content
matchers + random-path false-positive suppression. Targets may be hostnames or
full URLs, supplied as args, with -l file, or piped on stdin.`,
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

		// Optionally seed candidate URLs from the Wayback Machine.
		if discWayback {
			targets = append(targets, harvestWayback(cmd.Context(), targets)...)
		}
		if len(targets) == 0 {
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

		count := 0
		discover.Run(cmd.Context(), client, targets, cfg, func(h discover.Hit) {
			count++
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
		})
		log.Info("discovery complete: %d endpoint(s) found", count)
		return nil
	},
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
	rootCmd.AddCommand(discoverCmd)
}
