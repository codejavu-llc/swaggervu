// Package mcpserver exposes SwaggerVu's bounded inspection and read-intent
// scanning capabilities over local stdio. Authority is fixed at startup.
package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/codejavu-llc/swaggervu/data"
	"github.com/codejavu-llc/swaggervu/internal/detect"
	"github.com/codejavu-llc/swaggervu/internal/discover"
	"github.com/codejavu-llc/swaggervu/internal/httpclient"
	"github.com/codejavu-llc/swaggervu/internal/redact"
	"github.com/codejavu-llc/swaggervu/internal/requestgen"
	"github.com/codejavu-llc/swaggervu/internal/scan"
	"github.com/codejavu-llc/swaggervu/internal/secrets"
	"github.com/codejavu-llc/swaggervu/internal/spec"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Config struct {
	Version      string
	AllowedHosts []string
	AllowedRoots []string
	AllowPrivate bool
	Active       bool
	MaxRequests  int64
	MaxBodyBytes int64
	Rate         float64
	Timeout      time.Duration
}

type Service struct {
	cfg      Config
	client   *httpclient.Client
	mu       sync.RWMutex
	runs     map[string][]scan.Result
	findings map[string]scan.Result
}

type sourceArgs struct {
	Source string `json:"source" jsonschema:"local OpenAPI file under an allowed root, or an allowlisted http(s) URL"`
}

type discoverArgs struct {
	Host  string `json:"host" jsonschema:"exact hostname from the server startup allowlist"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum high-confidence paths, 1 through 25"`
}

type findingArgs struct {
	FindingID string `json:"finding_id" jsonschema:"server-minted SwaggerVu finding ID"`
}

type reportArgs struct {
	RunID string `json:"run_id" jsonschema:"server-minted SwaggerVu run ID"`
}

type InspectOutput struct {
	SchemaVersion   string            `json:"schema_version"`
	Source          string            `json:"source"`
	Kind            spec.Kind         `json:"kind"`
	Version         string            `json:"version"`
	Title           string            `json:"title"`
	Endpoints       []string          `json:"endpoints"`
	SecuritySchemes []string          `json:"security_schemes,omitempty"`
	Secrets         []secrets.Finding `json:"secrets,omitempty"`
}

type DiscoverOutput struct {
	SchemaVersion string         `json:"schema_version"`
	Hits          []discover.Hit `json:"hits"`
	RequestsLimit int            `json:"requests_limit"`
}

type PlannedRequest struct {
	Method       string `json:"method"`
	URL          string `json:"url"`
	Path         string `json:"path"`
	RequiresAuth bool   `json:"requires_auth"`
}

type PlanOutput struct {
	SchemaVersion string           `json:"schema_version"`
	Requests      []PlannedRequest `json:"requests"`
	Active        bool             `json:"active_authorized_at_startup"`
}

type ScanOutput struct {
	SchemaVersion string        `json:"schema_version"`
	RunID         string        `json:"run_id"`
	Findings      []scan.Result `json:"findings"`
}

type FindingOutput struct {
	SchemaVersion string      `json:"schema_version"`
	Found         bool        `json:"found"`
	Finding       scan.Result `json:"finding"`
}

type ReportOutput struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	Markdown      string `json:"markdown"`
}

func New(cfg Config) (*Service, error) {
	if len(cfg.AllowedHosts) == 0 && len(cfg.AllowedRoots) == 0 {
		return nil, fmt.Errorf("MCP requires at least one --allow-host or --allow-root")
	}
	roots, err := canonicalRoots(cfg.AllowedRoots)
	if err != nil {
		return nil, err
	}
	cfg.AllowedRoots = roots
	hosts, err := httpclient.NormalizeAllowedHosts(cfg.AllowedHosts)
	if err != nil {
		return nil, err
	}
	cfg.AllowedHosts = hosts
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = 100
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 2 << 20
	}
	if cfg.Rate <= 0 {
		cfg.Rate = 5
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	opts := httpclient.DefaultOptions()
	opts.Timeout = cfg.Timeout
	opts.RatePerSecond = cfg.Rate
	opts.AllowedHosts = append([]string(nil), cfg.AllowedHosts...)
	opts.AllowPrivate = cfg.AllowPrivate
	opts.MaxRequests = cfg.MaxRequests
	opts.MaxBodyBytes = cfg.MaxBodyBytes
	opts.FollowRedirect = true
	client, err := httpclient.New(opts)
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, client: client, runs: map[string][]scan.Result{}, findings: map[string]scan.Result{}}, nil
}

func canonicalRoots(roots []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		absRoot, err := filepath.Abs(root)
		if err != nil {
			return nil, fmt.Errorf("resolve --allow-root: %w", err)
		}
		absRoot, err = filepath.EvalSymlinks(filepath.Clean(absRoot))
		if err != nil {
			return nil, fmt.Errorf("resolve --allow-root %q: %w", root, err)
		}
		info, err := os.Stat(absRoot)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("--allow-root %q must be an existing directory", root)
		}
		if !seen[absRoot] {
			seen[absRoot] = true
			out = append(out, absRoot)
		}
	}
	return out, nil
}

func (s *Service) Server() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "swaggervu", Version: s.cfg.Version}, nil)
	s.addTools(server)
	s.addResources(server)
	return server
}

func (s *Service) Run(ctx context.Context) error {
	return s.Server().Run(ctx, &mcp.StdioTransport{})
}

func (s *Service) addTools(server *mcp.Server) {
	mcp.AddTool(server, tool("inspect_spec", "Parse and inventory an allowed OpenAPI/Swagger source without executing its operations", true, false),
		func(ctx context.Context, _ *mcp.CallToolRequest, args sourceArgs) (*mcp.CallToolResult, InspectOutput, error) {
			out, err := s.inspect(ctx, args.Source, false)
			return nil, out, err
		})
	mcp.AddTool(server, tool("audit_spec", "Inspect a description and report redacted embedded-secret signals", true, false),
		func(ctx context.Context, _ *mcp.CallToolRequest, args sourceArgs) (*mcp.CallToolResult, InspectOutput, error) {
			out, err := s.inspect(ctx, args.Source, true)
			return nil, out, err
		})
	mcp.AddTool(server, tool("discover_docs", "Probe a bounded high-confidence path set on one startup-allowlisted host", true, true),
		func(ctx context.Context, _ *mcp.CallToolRequest, args discoverArgs) (*mcp.CallToolResult, DiscoverOutput, error) {
			out, err := s.discover(ctx, args)
			return nil, out, err
		})
	mcp.AddTool(server, tool("plan_scan", "List the exact GET/HEAD requests a read-intent scan would send; sends none", true, false),
		func(ctx context.Context, _ *mcp.CallToolRequest, args sourceArgs) (*mcp.CallToolResult, PlanOutput, error) {
			out, err := s.plan(ctx, args.Source)
			return nil, out, err
		})
	mcp.AddTool(server, tool("run_readonly_scan", "Execute the startup-authorized GET/HEAD request profile within fixed scope and budget", false, true),
		func(ctx context.Context, _ *mcp.CallToolRequest, args sourceArgs) (*mcp.CallToolResult, ScanOutput, error) {
			out, err := s.runScan(ctx, args.Source)
			return nil, out, err
		})
	mcp.AddTool(server, tool("get_finding", "Retrieve one sanitized finding by server-minted ID", true, false),
		func(_ context.Context, _ *mcp.CallToolRequest, args findingArgs) (*mcp.CallToolResult, FindingOutput, error) {
			s.mu.RLock()
			finding, ok := s.findings[args.FindingID]
			s.mu.RUnlock()
			return nil, FindingOutput{SchemaVersion: "swaggervu.mcp.finding/v1", Found: ok, Finding: finding}, nil
		})
	mcp.AddTool(server, tool("render_report", "Render a sanitized Markdown report for a completed run", true, false),
		func(_ context.Context, _ *mcp.CallToolRequest, args reportArgs) (*mcp.CallToolResult, ReportOutput, error) {
			out, err := s.report(args.RunID)
			return nil, out, err
		})
}

func tool(name, description string, readOnly, openWorld bool) *mcp.Tool {
	destructive := false
	return &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: readOnly, DestructiveHint: &destructive, IdempotentHint: readOnly, OpenWorldHint: &openWorld,
	}}
}

func (s *Service) inspect(ctx context.Context, source string, audit bool) (InspectOutput, error) {
	doc, err := s.load(ctx, source)
	if err != nil {
		return InspectOutput{}, err
	}
	out := InspectOutput{SchemaVersion: "swaggervu.mcp.inspect/v1", Source: redact.URL(source), Kind: doc.Kind, Version: doc.Version, Title: redact.Text(doc.Title)}
	for _, endpoint := range detect.Endpoints(doc) {
		out.Endpoints = append(out.Endpoints, redact.Text(endpoint))
	}
	if doc.Doc != nil && doc.Doc.Components != nil {
		for name := range doc.Doc.Components.SecuritySchemes {
			out.SecuritySchemes = append(out.SecuritySchemes, redact.Text(name))
		}
		sort.Strings(out.SecuritySchemes)
	}
	if audit {
		if raw, err := json.Marshal(doc.Raw); err == nil {
			out.Secrets = secrets.Scan(string(raw))
		}
	}
	return out, nil
}

func (s *Service) discover(ctx context.Context, args discoverArgs) (DiscoverOutput, error) {
	limit := args.Limit
	if limit <= 0 || limit > 25 {
		limit = 25
	}
	paths := data.Paths()
	if len(paths) > limit {
		paths = paths[:limit]
	}
	var hits []discover.Hit
	discover.Run(ctx, s.client, []string{args.Host}, discover.Config{Concurrency: 5, Mixed: false, Paths: paths}, func(hit discover.Hit) {
		hit.URL = redact.URL(hit.URL)
		hits = append(hits, hit)
	})
	return DiscoverOutput{SchemaVersion: "swaggervu.mcp.discover/v1", Hits: hits, RequestsLimit: limit + 2}, nil
}

func (s *Service) plan(ctx context.Context, source string) (PlanOutput, error) {
	doc, err := s.load(ctx, source)
	if err != nil {
		return PlanOutput{}, err
	}
	reqs := requestgen.Build(doc, requestgen.DefaultOptions())
	out := PlanOutput{SchemaVersion: "swaggervu.mcp.plan/v1", Active: s.cfg.Active}
	for _, req := range reqs {
		out.Requests = append(out.Requests, PlannedRequest{Method: req.Method, URL: redact.URL(req.URL), Path: redact.Text(req.Path), RequiresAuth: req.RequiresAuth})
	}
	return out, nil
}

func (s *Service) runScan(ctx context.Context, source string) (ScanOutput, error) {
	if !s.cfg.Active {
		return ScanOutput{}, fmt.Errorf("run_readonly_scan is disabled; restart MCP with --active after authorization and scope review")
	}
	doc, err := s.load(ctx, source)
	if err != nil {
		return ScanOutput{}, err
	}
	var findings []scan.Result
	var findingsMu sync.Mutex
	scan.Run(ctx, s.client, doc, scan.Config{Concurrency: 5, GenOpts: requestgen.DefaultOptions()}, func(result scan.Result) {
		if result.Interesting {
			findingsMu.Lock()
			findings = append(findings, result)
			findingsMu.Unlock()
		}
	})
	runID := runID(source, findings)
	s.mu.Lock()
	s.runs[runID] = append([]scan.Result(nil), findings...)
	for _, finding := range findings {
		s.findings[finding.FindingID] = finding
	}
	s.mu.Unlock()
	return ScanOutput{SchemaVersion: "swaggervu.mcp.scan/v1", RunID: runID, Findings: findings}, nil
}

func runID(source string, findings []scan.Result) string {
	base := fmt.Sprintf("%s\x00%d\x00%d", source, len(findings), time.Now().UnixNano())
	sum := sha256.Sum256([]byte(base))
	return fmt.Sprintf("run-%x", sum[:8])
}

func (s *Service) report(runID string) (ReportOutput, error) {
	s.mu.RLock()
	findings, ok := s.runs[runID]
	s.mu.RUnlock()
	if !ok {
		return ReportOutput{}, fmt.Errorf("unknown run ID")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# SwaggerVu MCP report\n\n- Run: `%s`\n- Findings: %d\n\n", runID, len(findings))
	for _, finding := range findings {
		fmt.Fprintf(&b, "## %s %s\n\n- ID: `%s`\n- Severity: %s\n- Confidence: %s\n- Evidence: %s\n- Signals: %s\n\n", finding.Method, finding.Path, finding.FindingID, finding.Severity, finding.Confidence, finding.EvidenceLevel, strings.Join(finding.Reasons, ", "))
	}
	return ReportOutput{SchemaVersion: "swaggervu.mcp.report/v1", RunID: runID, Markdown: b.String()}, nil
}

func (s *Service) load(ctx context.Context, source string) (*spec.Spec, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		resp, err := s.client.Get(ctx, source)
		if err != nil {
			return nil, err
		}
		if resp.Status < 200 || resp.Status >= 300 {
			return nil, fmt.Errorf("spec returned HTTP %d", resp.Status)
		}
		return spec.Load(resp.Body, source)
	}
	path, err := s.allowedFile(source)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > s.cfg.MaxBodyBytes {
		return nil, fmt.Errorf("local spec exceeds %d-byte limit", s.cfg.MaxBodyBytes)
	}
	body, err := os.ReadFile(path) // #nosec G304 -- path was canonicalized and scope-checked above
	if err != nil {
		return nil, err
	}
	return spec.Load(body, path)
}

func (s *Service) allowedFile(source string) (string, error) {
	path, err := filepath.Abs(source)
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	for _, root := range s.cfg.AllowedRoots {
		absRoot, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		absRoot, err = filepath.EvalSymlinks(filepath.Clean(absRoot))
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(absRoot, path)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return path, nil
		}
	}
	return "", fmt.Errorf("local file is outside configured --allow-root scope")
}

func (s *Service) addResources(server *mcp.Server) {
	resources := map[string]struct{ name, description, text string }{
		"swaggervu://policy":             {"policy", "Immutable MCP startup authority", s.policyJSON()},
		"swaggervu://schemas/finding-v1": {"finding-schema", "SwaggerVu finding schema summary", `{"schema_version":"swaggervu.finding/v1","required":["schema_version","method","url","path","status","reasons"]}`},
		"swaggervu://catalog/rules":      {"rule-catalog", "Bundled signal categories", `["embedded-secret","server-internal-leak","anonymous-data-signal","authorization-differential"]`},
	}
	for uri, item := range resources {
		uri, item := uri, item
		server.AddResource(&mcp.Resource{URI: uri, Name: item.name, Description: item.description, MIMEType: "application/json"},
			func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "application/json", Text: item.text}}}, nil
			})
	}
}

func (s *Service) policyJSON() string {
	value := map[string]any{"allowed_hosts": s.cfg.AllowedHosts, "allowed_roots": s.cfg.AllowedRoots, "allow_private": s.cfg.AllowPrivate, "active": s.cfg.Active, "max_requests": s.cfg.MaxRequests, "max_body_bytes": s.cfg.MaxBodyBytes, "rate": s.cfg.Rate}
	body, _ := json.Marshal(value)
	return string(body)
}
