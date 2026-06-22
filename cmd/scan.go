package cmd

import (
	"fmt"
	"strings"

	"github.com/codejavu-inc/swaggervu/internal/output"
	"github.com/codejavu-inc/swaggervu/internal/requestgen"
	"github.com/codejavu-inc/swaggervu/internal/scan"
	"github.com/spf13/cobra"
)

var (
	scanURL     string
	scanRisk    bool
	scanBase    string
	scanShowAll bool
	scanMD      bool
	scanAuth    []string
)

var scanCmd = &cobra.Command{
	Use:   "scan [url|file]",
	Short: "Audit an API: fire one request per operation, flag unauth & data leaks",
	Long: `Generate a request for every operation in the spec and report which
endpoints are reachable without auth (401/403 are skipped) and which leak data
or secrets. Destructive methods (POST/PUT/PATCH/DELETE) are skipped unless --risk is set.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		src := scanURL
		if src == "" && len(args) > 0 {
			src = args[0]
		}
		if src == "" {
			return fmt.Errorf("provide a URL or file (positional arg or -u)")
		}
		log.Banner(version)

		s, err := loadSpecFromSource(cmd.Context(), src)
		if err != nil {
			return err
		}
		log.Info("loaded %s '%s' — auditing endpoints", s.Kind, s.Title)

		client, err := buildClient(false)
		if err != nil {
			return err
		}
		// --md takes precedence over --json so the two can't garble each other.
		sink, err := output.NewSink(flagOutput, flagJSON && !scanMD)
		if err != nil {
			return err
		}
		defer sink.Close()

		genOpts := requestgen.DefaultOptions()
		genOpts.BaseURL = scanBase
		cfg := scan.Config{
			Concurrency: flagConcurrency,
			IncludeRisk: scanRisk,
			EmitAll:     scanShowAll,
			AuthHeaders: parseHeaders(scanAuth),
			GenOpts:     genOpts,
		}
		if len(cfg.AuthHeaders) > 0 {
			log.Info("auth-aware mode: probing each endpoint with and without auth to detect broken access control")
		}

		interesting := 0
		var results []scan.Result
		scan.Run(cmd.Context(), client, s, cfg, func(r scan.Result) {
			if r.Interesting {
				interesting++
				results = append(results, r)
				tag := ""
				if len(r.Reasons) > 0 {
					tag = " [" + strings.Join(r.Reasons, ", ") + "]"
				}
				log.Good("%s  %d bytes  %s %s%s", output.Status(r.Status), r.ContentLength, r.Method, r.URL, tag)
			} else if scanShowAll {
				log.Info("%s  %d bytes  %s %s", output.Status(r.Status), r.ContentLength, r.Method, r.URL)
			}
			if scanMD {
				return // markdown is rendered once after the run
			}
			if flagJSON {
				sink.Add(r)
			} else if r.Interesting {
				sink.WriteLine(fmt.Sprintf("%s %s [%d]", r.Method, r.URL, r.Status))
			}
		})
		if scanMD {
			sink.WriteLine(renderScanMarkdown(s, src, results))
		}
		log.Info("scan complete: %d interesting endpoint(s)", interesting)
		return nil
	},
}

func init() {
	f := scanCmd.Flags()
	f.StringVarP(&scanURL, "url", "u", "", "URL or file of the API definition")
	f.BoolVar(&scanRisk, "risk", false, "include non-GET methods (POST/PUT/PATCH/DELETE) — use with care")
	f.BoolVarP(&scanShowAll, "show-all", "V", false, "log every probed request, not just findings (incl. non-200; non-GET methods need --risk)")
	f.StringVar(&scanBase, "base-url", "", "override the API base/server URL")
	f.BoolVar(&scanMD, "md", false, "emit a paste-ready Markdown report of findings (use with -o report.md)")
	f.StringArrayVar(&scanAuth, "auth", nil, "auth header for an authenticated comparison run, repeatable (e.g. --auth 'Authorization: Bearer TOKEN'); enables broken-access-control detection")
	rootCmd.AddCommand(scanCmd)
}
