# Changelog

All notable changes to SwaggerVu are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/codejavu-llc/swaggervu/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/codejavu-llc/swaggervu/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/codejavu-llc/swaggervu/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/codejavu-llc/swaggervu/releases/tag/v1.0.0
