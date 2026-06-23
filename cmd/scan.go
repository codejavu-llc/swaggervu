package cmd

import (
	"fmt"
	"strings"

	"github.com/codejavu-llc/swaggervu/internal/detect"
	"github.com/codejavu-llc/swaggervu/internal/output"
	"github.com/codejavu-llc/swaggervu/internal/requestgen"
	"github.com/codejavu-llc/swaggervu/internal/scan"
	"github.com/codejavu-llc/swaggervu/internal/secrets"
	"github.com/codejavu-llc/swaggervu/internal/spec"
	"github.com/spf13/cobra"
)

var (
	scanURL     string
	scanRisk    bool
	scanBase    string
	scanShowAll bool
	scanMD      bool
	scanAuth    []string
	scanEmit    string
)

var scanCmd = &cobra.Command{
	Use:   "scan [url|file]",
	Short: "Audit an API: fire one request per operation, flag unauth & data leaks",
	Long: `Generate a request for every operation in the spec and report which
endpoints are reachable without auth (401/403 are skipped) and which leak data
or secrets. The spec document itself is also scanned for hardcoded credentials.
Destructive methods (POST/PUT/PATCH/DELETE) are skipped unless --risk is set.

Use --emit curl|sqlmap to print ready-to-run commands instead of scanning (no
requests are sent).`,
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

		// --emit is print-only: emit ready-to-run commands and fire nothing.
		// This must short-circuit before any network/secret work so that, e.g.,
		// `scan --emit sqlmap --risk` prints destructive requests without sending.
		if scanEmit != "" {
			if scanEmit != "curl" && scanEmit != "sqlmap" {
				return fmt.Errorf("--emit must be 'curl' or 'sqlmap', got %q", scanEmit)
			}
			opts := requestgen.DefaultOptions()
			opts.IncludeRisk = scanRisk
			for _, r := range requestgen.Build(s, opts) {
				fmt.Println(commandFor(scanEmit, r))
			}
			return nil
		}
		log.Info("loaded %s '%s' — auditing endpoints", s.Kind, s.Title)

		// Secrets embedded in the spec document itself (titles, descriptions,
		// examples, server URLs). The per-response secret scan happens inside
		// scan.Run; this catches creds hardcoded in the definition — matching `all`.
		for _, f := range scanSpecDocument(s) {
			log.Warn("spec secret %s: %s", f.Type, f.Match)
		}

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

// scanSpecDocument scans the spec's own text (title, endpoint paths, and the
// raw definition) for hardcoded credentials. Mirrors the standalone `secrets`.
func scanSpecDocument(s *spec.Spec) []secrets.Finding {
	var corpus strings.Builder
	corpus.WriteString(s.Title + "\n")
	for _, e := range detect.Endpoints(s) {
		corpus.WriteString(e + "\n")
	}
	if b, err := marshalRaw(s.Raw); err == nil {
		corpus.Write(b)
	}
	return secrets.Scan(corpus.String())
}

func init() {
	f := scanCmd.Flags()
	f.StringVarP(&scanURL, "url", "u", "", "URL or file of the API definition")
	f.StringVar(&scanEmit, "emit", "", "print-only: emit ready-to-run commands instead of scanning ('curl' or 'sqlmap')")
	f.BoolVar(&scanRisk, "risk", false, "include non-GET methods (POST/PUT/PATCH/DELETE) — use with care")
	f.BoolVarP(&scanShowAll, "show-all", "V", false, "log every probed request, not just findings (incl. non-200; non-GET methods need --risk)")
	f.StringVar(&scanBase, "base-url", "", "override the API base/server URL")
	f.BoolVar(&scanMD, "md", false, "emit a paste-ready Markdown report of findings (use with -o report.md)")
	f.StringArrayVar(&scanAuth, "auth", nil, "auth header for an authenticated comparison run, repeatable (e.g. --auth 'Authorization: Bearer TOKEN'); enables broken-access-control detection")
	rootCmd.AddCommand(scanCmd)
}
