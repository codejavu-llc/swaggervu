# Changelog

All notable changes to SwaggerVu are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Bare-command inventory now warns in its text and JSON signals when relaxed
  OpenAPI loading may leave the operation list incomplete, including in quiet mode.
  External spec references remain unsupported.

- `scan` now reports request-limit refusals and other request errors in an
  incomplete-run notice on stderr, including in quiet mode and when a comparison
  request cannot finish. Completed result rows, JSON format and exit behavior
  remain unchanged.

- Clarified `--max-requests` in command help and the README: redirects followed
  for one logical request share its budget unit. The option does not cap each
  HTTP exchange separately. Counting behavior and defaults are unchanged.

- Use Go 1.26.11 for CI and releases, including the standard-library security
  fixes needed by the vulnerability gate.

### Fixed

- Resolve same-document Swagger 2.0 Path Item references before conversion, so
  operation inventories and diffs retain referenced operations. Invalid or cyclic
  references now report an error instead of silently omitting operations.
  External Path Item references remain unsupported and report an error.

- Do not classify a response as anonymous access when its request carried a
  nonempty credential-like header. Apply the same rule to the baseline of auth
  comparisons, preserving other response evidence and existing request behavior.

- Report output-write failures from `diff` in both JSON and text modes instead
  of returning success when its stdout result cannot be delivered.

- Honor operation and path server settings when generating requests, while
  preserving explicit `--base-url` overrides and the document server default.

- Share the command request budget across HTTP clients, so downloading a
  description and requesting its operations use the same `--max-requests` limit.

- Load OpenAPI 3.1 boolean schemas by adapting them to equivalent schema
  objects, while preserving ordinary boolean values and the original raw input.

- Redact matched values in added and removed operation labels in JSON and text
  comparison output, while comparing original operations to preserve real changes.

- Honor form-style array encoding in generated URL-encoded request bodies,
  using repeated fields by default and comma-joined values for `explode: false`.

- Honor `scan --base-url` when printing curl or sqlmap commands with `--emit`.

- Preserve ordinary apostrophes in generated curl and sqlmap arguments using
  POSIX-style shell quoting.

- Report a readable error for empty or null input documents instead of a formatting
  diagnostic, while preserving invalid-input rejection and underlying parse errors.

- Treat an empty security alternative as optional authentication, including when
  it appears alongside named schemes, while preserving operation-level overrides.

- Keep MCP network work disabled when no startup `--allow-host` is supplied,
  including remote description loads, discovery and active scan calls. Local
  description workflows and explicitly allowed host workflows remain available.

- Reject same-document Swagger 2.0 Path Item references to unrelated
  document objects, rather than silently treating them as empty paths.

- Keep the scan host-root fallback from rerouting operation-server requests
  to the description source host.

## [1.1.0-rc.1] - 2026-08-22

### Added

- Simple bare-command workflow: local/remote spec inventory, or a bounded HTTPS-only
  25-path documentation check for a hostname.
- `diff` for added/removed operations and `doctor` for installation/browser checks.
- Local stdio MCP server with seven structured tools, immutable hostname/filesystem
  scope, request and body budgets, DNS/private-address defenses, safe-root resolution,
  resources, protocol tests, and an explicit startup gate for GET/HEAD execution.
- Versioned finding, inspect, diff, and MCP output contracts; stable finding IDs,
  confidence, evidence levels, and finding status.
- OpenAPI 3.2 detection and inventory fixture coverage; parser/runtime dependencies
  updated to current releases.
- Syft SBOMs and GitHub build-provenance attestations for release archives.
- Pinned-action CI, CodeQL, dependency review, Dependabot, race tests, fuzz seed
  corpora, gosec, govulncheck, cross-platform builds, and community templates.

### Changed

- `scan` now requires `--active`; non-GET/HEAD methods still additionally require
  `--risk`. The hidden legacy `all` command also requires `--active`, and its browser
  phase requires `--verify`.
- `exploit` is now presented as `verify` (`exploit` remains an alias) and uses a local,
  process-bound benign PoC by default instead of third-party payload hosts.
- Active default generation is restricted to GET/HEAD. Output language now describes
  response-size and auth comparisons as signals/differentials rather than BOLA or
  confirmed broken access control.
- Sensitive headers and auth comparisons require an exact `--auth-origin`; redirects
  are same-origin and response bodies are capped.
- External OpenAPI references remain disabled until they can use the same scoped
  resolver policy.

### Security

- Secret values are never stored in findings. Outputs contain a process-local HMAC
  fingerprint and length only; the compatibility `match` field is always redacted.
- URL userinfo is removed and every query value is replaced before logging, JSON, MCP,
  or Markdown output. Browser console content is no longer serialized. Evidence files
  use owner-only permissions.
- Public network access denies private and special-use addresses by default and
  revalidates DNS at dial time to reduce SSRF and DNS-rebinding risk.
- Browser TLS verification follows the explicit global `--insecure` choice. Ambient
  JavaScript dialogs no longer count as XSS evidence.

### Fixed

- Corrected the CVE registry: CVE-2025-8191 is application-specific, CVE-2018-25031
  is remote-definition spoofing, and the testable remote-spec XSS chain is
  CVE-2025-54432. Catalog-only entries are no longer presented as executed checks.
- Relaxed parsing no longer deletes security declarations to make an invalid spec load.
- Remote-spec payload query parameters are URL-encoded correctly.

## [1.0.2] - 2026-06-23

### Changed
- **Consolidated to 5 commands**: `discover`, `detect`, `scan`, `exploit`, `all`.
  The former standalone commands are now flags/sources on these (and remain as
  hidden aliases for script compatibility):
  - `wayback <domain>` → `discover --wayback`
  - `osint <term>` → `discover --osint`
  - `secrets <spec>` → automatic in `scan` (now scans the spec document too)
  - `prepare <spec>` → `scan --emit curl|sqlmap` (print-only, sends nothing)
- The auto-generated `completion` command is hidden from help (still functional).

### Added
- Live progress on `discover` (and `all` phase 1): a single updating line with
  hosts probed / total, hits, and elapsed time (TTY only; pipes stay clean).
- `scan` now scans the spec **document** for hardcoded secrets, not just live
  responses — matching `all`.

### Fixed
- Wayback/OSINT candidate URLs are now **direct-probed** instead of being treated
  as hosts and having the wordlist appended (which never fetched the real spec
  URL). Closes a latent bug in both `discover --wayback` and the `all` autopilot's
  Wayback seeding.
- `--version` and the banner report the real build version via Go build info for
  `go install` builds, instead of a hardcoded value.

## [1.0.1]

### Fixed
- Corrected the Go module path to `github.com/codejavu-llc/swaggervu` so
  `go install github.com/codejavu-llc/swaggervu@latest` works. The `v1.0.0`
  tag shipped a `go.mod` still declaring the old `codejavu-inc` path, which
  caused a "module declares its path as …" version conflict.

### Added
- **Auth-aware scanning** (`scan`/`all` `--auth "Header: Value"`, repeatable):
  probes each endpoint without and with the token to detect **broken access
  control** — operations the spec marks as auth-required that still return data
  unauthenticated, and endpoints whose response ignores the token entirely.
- `--md` Markdown report mode for `scan` and `all` (paste-ready writeups).
- Sharper scan heuristics: stack-trace / SQL / framework-error / debug-page
  detection at any status, plus HTML-shell false-positive suppression.
- Modern discovery paths (Quarkus, Kubernetes, Scalar, springdoc) and secret
  patterns (GitLab, OpenAI, Anthropic, SendGrid, Shopify, DigitalOcean, …).
- GitHub Actions CI (build · vet · test) and tagged release binaries via GoReleaser.
- `SECURITY.md`, `CONTRIBUTING.md`, issue templates.

### Changed
- `discover` probes both http and https for bare hosts by default (`--https-only`
  to restrict; `-m`/`--mixed` deprecated as it is now the default).
- `exploit` injects bundled hosted PoC specs by default (override via
  `SWAGGERVU_PAYLOAD_*`, `--payload`, or `--builtin-payload` for the local PoC).

## [1.0.0]

### Added
- `all` autopilot: one command runs discover → parse → audit → secrets → exploit.
- `discover` mass Swagger/OpenAPI discovery with content matchers and random-path baselining.
- `wayback` archived-URL harvesting; `osint` SwaggerHub spec discovery.
- `detect`/`parse` for Swagger 2.0, OpenAPI 3.0 & 3.1 (JSON/YAML/JS-embedded), with v2→v3 conversion.
- `scan` unauthenticated data-exposure & secret auditing (skip-401/403, BOLA heuristic).
- `secrets` TruffleHog-style + SwaggerSpy regex corpus over specs and live responses.
- `exploit` headless-confirmed Swagger-UI client-side CVE testing with screenshot evidence.
- `prepare` curl/sqlmap command emission per endpoint.
- Global rate-limited, concurrent HTTP client shared across modules.

[Unreleased]: https://github.com/codejavu-llc/swaggervu/compare/v1.1.0-rc.1...HEAD
[1.1.0-rc.1]: https://github.com/codejavu-llc/swaggervu/compare/v1.0.2...v1.1.0-rc.1
[1.0.2]: https://github.com/codejavu-llc/swaggervu/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/codejavu-llc/swaggervu/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/codejavu-llc/swaggervu/releases/tag/v1.0.0
