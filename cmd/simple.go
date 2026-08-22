package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/codejavu-llc/swaggervu/data"
	"github.com/codejavu-llc/swaggervu/internal/detect"
	"github.com/codejavu-llc/swaggervu/internal/discover"
	"github.com/codejavu-llc/swaggervu/internal/redact"
	"github.com/codejavu-llc/swaggervu/internal/secrets"
	"github.com/codejavu-llc/swaggervu/internal/spec"
	"github.com/spf13/cobra"
)

type inspectReport struct {
	SchemaVersion   string            `json:"schema_version"`
	Source          string            `json:"source"`
	Kind            spec.Kind         `json:"kind"`
	Version         string            `json:"version"`
	Title           string            `json:"title"`
	Endpoints       []string          `json:"endpoints"`
	SecuritySchemes []string          `json:"security_schemes,omitempty"`
	Signals         []string          `json:"signals,omitempty"`
	Secrets         []secrets.Finding `json:"secrets,omitempty"`
}

func runSimple(cmd *cobra.Command, input string) error {
	log.Banner(version)
	if isHostInput(input) {
		return inspectHost(cmd, input)
	}
	s, err := loadSpecFromSource(cmd.Context(), input)
	if err != nil {
		return err
	}
	return emitInspection(inspectSpec(s, input))
}

func isHostInput(input string) bool {
	if strings.Contains(input, "://") {
		return false
	}
	if _, err := os.Stat(input); err == nil {
		return false
	}
	return !strings.ContainsAny(input, "/\\?#@")
}

func inspectHost(cmd *cobra.Command, host string) error {
	log.Info("bounded inspect plan: up to 25 high-confidence paths on https://%s; no API operations or browser payloads", host)
	client, err := buildClient(false)
	if err != nil {
		return err
	}
	paths := data.Paths()
	if len(paths) > 25 {
		paths = paths[:25]
	}
	var hits []discover.Hit
	discover.Run(cmd.Context(), client, []string{host}, discover.Config{
		Concurrency: min(flagConcurrency, 10),
		Mixed:       false,
		Paths:       paths,
	}, func(hit discover.Hit) { hits = append(hits, hit) })
	if len(hits) == 0 {
		return fmt.Errorf("no Swagger/OpenAPI resource found in the bounded quick check; use 'swaggervu discover %s' for full discovery", host)
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].URL < hits[j].URL })
	for _, hit := range hits {
		if !hit.IsSpec {
			log.Good("docs UI: %s", redact.URL(hit.URL))
			continue
		}
		s, err := loadSpecFromSource(cmd.Context(), hit.URL)
		if err == nil {
			return emitInspection(inspectSpec(s, hit.URL))
		}
	}
	log.Good("found %d documentation resource(s); use the reported URL with 'swaggervu <url>' for inspection", len(hits))
	return nil
}

func inspectSpec(s *spec.Spec, source string) inspectReport {
	r := inspectReport{
		SchemaVersion: "swaggervu.inspect/v1",
		Source:        redact.URL(source),
		Kind:          s.Kind,
		Version:       s.Version,
		Title:         redact.Text(s.Title),
		Secrets:       scanSpecDocument(s),
	}
	for _, endpoint := range detect.Endpoints(s) {
		r.Endpoints = append(r.Endpoints, redact.Text(endpoint))
	}
	if s.Doc != nil && s.Doc.Components != nil {
		for name := range s.Doc.Components.SecuritySchemes {
			r.SecuritySchemes = append(r.SecuritySchemes, redact.Text(name))
		}
		sort.Strings(r.SecuritySchemes)
	}
	for _, raw := range serverURLs(s) {
		u, err := url.Parse(raw)
		if err == nil && u.Scheme == "http" {
			r.Signals = append(r.Signals, "plaintext server URL: "+redact.URL(raw))
		}
	}
	if len(r.SecuritySchemes) == 0 {
		r.Signals = append(r.Signals, "no security schemes declared")
	}
	if len(r.Secrets) > 0 {
		r.Signals = append(r.Signals, fmt.Sprintf("%d possible embedded secret(s), values redacted", len(r.Secrets)))
	}
	return r
}

func serverURLs(s *spec.Spec) []string {
	if s == nil || s.Doc == nil {
		return nil
	}
	out := make([]string, 0, len(s.Doc.Servers))
	for _, server := range s.Doc.Servers {
		if server != nil {
			out = append(out, server.URL)
		}
	}
	return out
}

func emitInspection(r inspectReport) error {
	var body []byte
	if flagJSON {
		encoded, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		body = append(encoded, '\n')
	} else {
		var b strings.Builder
		fmt.Fprintf(&b, "Type:      %s (%s)\n", r.Kind, r.Version)
		fmt.Fprintf(&b, "Title:     %s\n", r.Title)
		fmt.Fprintf(&b, "Endpoints: %d\n", len(r.Endpoints))
		if len(r.SecuritySchemes) > 0 {
			fmt.Fprintf(&b, "Security:  %s\n", strings.Join(r.SecuritySchemes, ", "))
		}
		if len(r.Signals) > 0 {
			b.WriteString("Signals:\n")
			for _, signal := range r.Signals {
				fmt.Fprintf(&b, "  ! %s\n", signal)
			}
		}
		for _, endpoint := range r.Endpoints {
			fmt.Fprintln(&b, "  "+endpoint)
		}
		body = []byte(b.String())
	}
	if flagOutput != "" {
		return writePrivateFile(flagOutput, body)
	}
	_, err := os.Stdout.Write(body)
	return err
}
