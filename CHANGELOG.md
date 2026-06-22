# Changelog

All notable changes to SwaggerVu are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/codejavu-inc/swaggervu/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/codejavu-inc/swaggervu/releases/tag/v1.0.0
