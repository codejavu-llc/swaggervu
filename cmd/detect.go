package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/codejavu-llc/swaggervu/internal/browser"
	"github.com/codejavu-llc/swaggervu/internal/detect"
	"github.com/codejavu-llc/swaggervu/internal/redact"
	"github.com/codejavu-llc/swaggervu/internal/spec"
	"github.com/spf13/cobra"
)

var (
	detectURL       string
	detectNoBrowser bool
)

var detectCmd = &cobra.Command{
	Use:     "detect [url|file]",
	Aliases: []string{"parse"},
	Short:   "Identify an API definition's type/version and list its endpoints",
	RunE: func(cmd *cobra.Command, args []string) error {
		src := detectURL
		if src == "" && len(args) > 0 {
			src = args[0]
		}
		if src == "" {
			return fmt.Errorf("provide a URL or file (positional arg or -u)")
		}
		log.Banner(version)

		s, err := loadSpecFromSourceMode(cmd.Context(), src, !detectNoBrowser)
		if err != nil {
			return err
		}
		fmt.Printf("Type:    %s\n", s.Kind)
		fmt.Printf("Version: %s\n", s.Version)
		fmt.Printf("Title:   %s\n", redact.Text(s.Title))
		eps := detect.Endpoints(s)
		fmt.Printf("Endpoints: %d\n", len(eps))
		for _, e := range eps {
			fmt.Println("  " + redact.Text(e))
		}
		return nil
	},
}

// loadSpecFromSource loads a spec from a local file or a URL.
func loadSpecFromSource(ctx context.Context, src string) (*spec.Spec, error) {
	return loadSpecFromSourceMode(ctx, src, false)
}

func loadSpecFromSourceMode(ctx context.Context, src string, allowBrowser bool) (*spec.Spec, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		client, err := buildClient(true)
		if err != nil {
			return nil, err
		}
		// If it's a UI page, follow to the real definition URL.
		res, err := detect.Inspect(ctx, client, src)
		if err != nil {
			return nil, err
		}
		if res.IsSpec {
			return res.Spec, nil
		}
		if res.IsUI && len(res.SpecURLs) > 0 {
			for _, su := range res.SpecURLs {
				if r2, err := detect.Inspect(ctx, client, su); err == nil && r2.IsSpec {
					return r2.Spec, nil
				}
			}
		}
		// Static parsing failed — the docs UI likely fetches its spec via
		// JavaScript after load. Fall back to a headless browser that watches
		// the network for the actual spec request (unless disabled).
		if allowBrowser {
			log.Info("static detection failed — loading %s headless to watch the network", src)
			br, err := browser.FindSpec(ctx, src, flagInsecure, 0)
			if err == nil && br.Spec != nil {
				log.Good("found spec via network capture: %s", redact.URL(br.SpecURL))
				return br.Spec, nil
			}
			if br != nil && len(br.Candidates) > 0 {
				log.Warn("saw %d spec-like request(s) but none parsed:", len(br.Candidates))
				for _, c := range br.Candidates {
					log.Warn("  %s", redact.URL(c))
				}
			}
		}
		return nil, fmt.Errorf("no parsable API definition found at %s", src)
	}
	info, err := os.Stat(src)
	if err != nil {
		return nil, err
	}
	limit := flagMaxBodyMB << 20
	if info.Size() > limit {
		return nil, fmt.Errorf("local description exceeds %d MiB limit", flagMaxBodyMB)
	}
	b, err := os.ReadFile(src) // #nosec G304 -- explicit operator-selected description
	if err != nil {
		return nil, err
	}
	return spec.Load(b, src)
}

func init() {
	detectCmd.Hidden = true
	detectCmd.Deprecated = "use 'swaggervu <spec-or-url>'"
	detectCmd.Flags().StringVarP(&detectURL, "url", "u", "", "URL or file of the API definition")
	detectCmd.Flags().BoolVar(&detectNoBrowser, "no-browser", false, "disable the headless-browser fallback for JS-rendered docs")
	rootCmd.AddCommand(detectCmd)
}
