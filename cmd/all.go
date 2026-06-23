package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/codejavu-llc/swaggervu/data"
	"github.com/codejavu-llc/swaggervu/internal/detect"
	"github.com/codejavu-llc/swaggervu/internal/discover"
	"github.com/codejavu-llc/swaggervu/internal/exploit"
	"github.com/codejavu-llc/swaggervu/internal/output"
	"github.com/codejavu-llc/swaggervu/internal/requestgen"
	"github.com/codejavu-llc/swaggervu/internal/scan"
	"github.com/codejavu-llc/swaggervu/internal/secrets"
	"github.com/codejavu-llc/swaggervu/internal/spec"
	"github.com/codejavu-llc/swaggervu/internal/wayback"
	"github.com/spf13/cobra"
)

var (
	allFile    string
	allRisk    bool
	allScreens string
	allShowAll bool
	allMD      bool
	allAuth    []string
)

// waybackAutoMax is the largest target count for which the autopilot auto-seeds
// from the Wayback Machine. Archive seeding is a single-domain recon step; doing
// it per-host across a big subdomain list is slow and gets rate-limited, so for
// larger lists it is skipped (use the standalone `wayback` command instead).
const waybackAutoMax = 20

// allReport is the structured result of an autopilot run.
type allReport struct {
	Domains  []string          `json:"domains"`
	Specs    []specReport      `json:"specs"`
	UIPages  []string          `json:"ui_pages"`
	Exploits []exploit.Finding `json:"exploits,omitempty"`
}

type specReport struct {
	URL         string            `json:"url"`
	Kind        spec.Kind         `json:"kind"`
	Title       string            `json:"title"`
	Endpoints   int               `json:"endpoints"`
	Interesting []scan.Result     `json:"interesting,omitempty"`
	Secrets     []secrets.Finding `json:"secrets,omitempty"`
}

var allCmd = &cobra.Command{
	Use:     "all <domain...>",
	Aliases: []string{"auto", "autopilot"},
	Short:   "Autopilot: one command runs every phase — discover, audit, secrets, exploit",
	Long: `Give it a domain and it does everything, no flags required: seed candidates
from the Wayback Machine, probe http+https for exposed Swagger/OpenAPI, parse every
spec, enumerate and audit endpoints (skipping 401/403), scan specs and responses for
leaked secrets, and confirm Swagger-UI client-side CVEs in a headless browser with a
benign built-in PoC.

For authorized testing only — you are responsible for every target you supply. Every
phase is non-destructive by default: it only reads, and the exploit phase fires a
self-contained XSS check (no data is exfiltrated). Destructive HTTP methods
(POST/PUT/PATCH/DELETE) are NEVER sent unless you opt in with --risk.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Banner(version)
		ctx := cmd.Context()

		targets, err := readTargets(allFile, args)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return fmt.Errorf("no domain provided (give a domain, -l file, or stdin)")
		}

		report := &allReport{Domains: targets}

		// ---- Seed candidates from the Wayback Machine (read-only) --------
		if len(targets) <= waybackAutoMax {
			wc, _ := buildClient(true)
			for _, t := range targets {
				if ctx.Err() != nil {
					break
				}
				if urls, err := wayback.Fetch(ctx, wc, t); err == nil && len(urls) > 0 {
					log.Info("wayback: +%d archived API URL(s) for %s", len(urls), t)
					targets = append(targets, urls...)
				}
			}
		} else {
			log.Info("skipping Wayback seed for %d targets (run a single domain, or the 'wayback' command, for archive seeding)", len(targets))
		}

		// ---- Phase 1: DISCOVER -------------------------------------------
		log.Info("phase 1/3 — discovering Swagger/OpenAPI across %d target(s)", len(targets))
		dc, err := buildClient(false)
		if err != nil {
			return err
		}
		specURLs := map[string]bool{}
		var uiPages []string
		uiSeen := map[string]bool{}
		var lastProg atomic.Int64
		progress := func(done, total int) {
			now := time.Now().Unix()
			prev := lastProg.Load()
			if done == total || (now-prev >= 2 && lastProg.CompareAndSwap(prev, now)) {
				log.Info("  ...probed %d/%d host(s)", done, total)
			}
		}
		discover.Run(ctx, dc, targets, discover.Config{Concurrency: flagConcurrency, Mixed: true, Progress: progress},
			func(h discover.Hit) {
				if h.IsSpec {
					if !specURLs[h.URL] {
						specURLs[h.URL] = true
						log.Good("spec: %s [%s] %s", h.URL, h.Kind, h.Title)
					}
				} else if !uiSeen[h.URL] {
					uiSeen[h.URL] = true
					uiPages = append(uiPages, h.URL)
					log.Good("ui:   %s", h.URL)
				}
			})
		report.UIPages = uiPages

		// Promote UI pages to specs by following them (static + headless fallback).
		sources := sortedKeys(specURLs)
		for _, ui := range uiPages {
			if s, err := loadSpecFromSource(ctx, ui); err == nil && s != nil && !specURLs[s.SourceURL] {
				specURLs[s.SourceURL] = true
				sources = append(sources, s.SourceURL)
			}
		}
		if len(sources) == 0 {
			log.Warn("no parsable API definitions found — nothing to audit")
		}

		// ---- Phase 2: PARSE + AUDIT + SECRETS per spec -------------------
		log.Info("phase 2/3 — parsing, auditing & secret-scanning %d spec(s)", len(sources))
		sc, _ := buildClient(false)
		// Skip specs that would fire an identical set of requests (e.g. the .json
		// and .yaml of the same API on one host). Two specs are duplicates when
		// they share an effective base URL and endpoint set; different hosts
		// (prod vs uat) differ in base and are still audited separately.
		auditedSig := map[string]bool{}
		for _, src := range sources {
			s, err := loadSpecFromSource(ctx, src)
			if err != nil || s == nil {
				continue
			}
			eps := detect.Endpoints(s)
			genOpts := requestgen.DefaultOptions()
			sig := requestgen.ResolveBase(s, genOpts) + "\x00" + strings.Join(eps, "\n")
			if auditedSig[sig] {
				log.Info("skipping %s — same API already audited (%d endpoints)", src, len(eps))
				continue
			}
			auditedSig[sig] = true
			sr := specReport{URL: src, Kind: s.Kind, Title: s.Title, Endpoints: len(eps)}
			log.Info("auditing %s — %s '%s' (%d endpoints)", src, s.Kind, s.Title, len(eps))

			scan.Run(ctx, sc, s, scan.Config{Concurrency: flagConcurrency, IncludeRisk: allRisk, EmitAll: allShowAll, AuthHeaders: parseHeaders(allAuth), GenOpts: genOpts},
				func(r scan.Result) {
					if r.Interesting {
						sr.Interesting = append(sr.Interesting, r)
						log.Good("  [%s] %d bytes  %s %s", output.Status(r.Status), r.ContentLength, r.Method, r.URL)
						for _, f := range r.Secrets {
							log.Warn("    secret %s: %s", f.Type, f.Match)
						}
					} else if allShowAll {
						log.Info("  [%s] %d bytes  %s %s", output.Status(r.Status), r.ContentLength, r.Method, r.URL)
					}
				})

			// Secrets in the spec document itself.
			if b, err := json.Marshal(s.Raw); err == nil {
				sr.Secrets = secrets.Scan(string(b))
				for _, f := range sr.Secrets {
					log.Warn("  spec secret %s: %s", f.Type, f.Match)
				}
			}
			report.Specs = append(report.Specs, sr)
		}

		// ---- Phase 3: EXPLOIT (benign PoC, headless) --------------------
		// Only swagger-ui pages can be DOM-XSS targets: a raw spec .json/.yaml URL
		// renders no UI, so configUrl/url injection can never fire against it —
		// those are dropped. UI pages are deduped case-insensitively (e.g. the
		// server serving both swagger/index.html and Swagger/index.html). Only fall
		// back to the raw target when a single domain was given — never fan a
		// headless browser out across a whole subdomain list that yielded no UI.
		candidates := dedupFold(uiPages)
		if len(candidates) == 0 && len(targets) == 1 {
			candidates = targets
		}
		log.Info("phase 3/3 — confirming client-side CVEs on %d candidate(s)", len(candidates))
		eng, err := exploit.New(allScreens)
		if err != nil {
			// Headless browser unavailable (e.g. Chrome not installed). Skip the
			// phase gracefully rather than failing the whole run.
			log.Warn("skipping exploit phase: headless browser unavailable (%v) — install Chrome/Chromium to enable it", err)
		} else {
			defer eng.Close()
			for _, c := range candidates {
				if ctx.Err() != nil {
					break
				}
				for _, param := range data.InjectionParams() {
					cves := strings.Join(data.CVEsForParam(param), ",")
					f := eng.Test(ctx, c, param, payloadFor(param, nil), cves, "", allScreens != "")
					if f.Vulnerable {
						log.Good("VULNERABLE [%s] %s via %s — %s (%s)", f.Type, c, param, cves, f.Signal)
						if f.Evidence != "" {
							log.Info("  evidence: %s", f.Evidence)
						}
						report.Exploits = append(report.Exploits, f)
					} else if f.CORSBlocked {
						log.Warn("CORS-BLOCKED %s via %s — retry with a CORS-permissive payload", c, param)
						report.Exploits = append(report.Exploits, f)
					}
				}
			}
		}

		// ---- Output ------------------------------------------------------
		printAllSummary(report)
		if allMD {
			md := renderAllMarkdown(report)
			if flagOutput != "" {
				return os.WriteFile(flagOutput, []byte(md), 0o644)
			}
			fmt.Println(md)
			return nil
		}
		if flagJSON || flagOutput != "" {
			return writeReport(report)
		}
		return nil
	},
}

func printAllSummary(r *allReport) {
	totalInteresting, totalSecrets := 0, 0
	for _, s := range r.Specs {
		totalInteresting += len(s.Interesting)
		totalSecrets += len(s.Secrets)
	}
	log.Info("──────── autopilot summary ────────")
	log.Info("specs found:           %d", len(r.Specs))
	log.Info("ui pages found:        %d", len(r.UIPages))
	log.Info("interesting endpoints: %d", totalInteresting)
	log.Info("spec secrets:          %d", totalSecrets)
	log.Info("confirmed exploits:    %d", countVuln(r.Exploits))
}

func countVuln(fs []exploit.Finding) int {
	n := 0
	for _, f := range fs {
		if f.Vulnerable {
			n++
		}
	}
	return n
}

func writeReport(r *allReport) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if flagOutput != "" {
		return os.WriteFile(flagOutput, b, 0o644)
	}
	fmt.Println(string(b))
	return nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// dedupFold returns in-order, non-empty strings with case-insensitive
// de-duplication, keeping the first-seen original spelling.
func dedupFold(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		k := strings.ToLower(s)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}

func init() {
	f := allCmd.Flags()
	f.StringVarP(&allFile, "list", "l", "", "file of domains/targets (one per line)")
	f.BoolVar(&allRisk, "risk", false, "also send non-GET methods (POST/PUT/PATCH/DELETE) — may modify target data")
	f.BoolVarP(&allShowAll, "show-all", "V", false, "log every probed request, not just findings (incl. non-200; non-GET methods need --risk)")
	f.StringVar(&allScreens, "screenshots", "", "directory to save exploit screenshot evidence")
	f.BoolVar(&allMD, "md", false, "emit a paste-ready Markdown report (use with -o report.md)")
	f.StringArrayVar(&allAuth, "auth", nil, "auth header for an authenticated comparison run, repeatable (e.g. --auth 'Authorization: Bearer TOKEN'); enables broken-access-control detection")
	rootCmd.AddCommand(allCmd)
}
