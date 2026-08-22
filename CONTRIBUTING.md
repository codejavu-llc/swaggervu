# Contributing to SwaggerVu

SwaggerVu welcomes code, fixtures, documentation, false-positive reports, discovery
paths, rules, and research. Small, focused pull requests are easiest to review.

By participating, follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Build and validate

SwaggerVu requires Go 1.26 or newer.

```bash
git clone https://github.com/codejavu-llc/swaggervu
cd swaggervu
go mod download
gofmt -w .
go vet ./...
go test -race ./...
go build ./...
```

Before opening a PR, also run these when practical:

```bash
go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 -quiet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

Chrome/Chromium is optional and needed only for browser-backed verification.

## Layout

```text
cmd/        CLI commands and rendering
data/       embedded discovery/rule/CVE catalog and provenance
internal/   network policy, parsing, scanning, redaction, browser, and MCP engines
schemas/    versioned machine-readable output/policy contracts
docs/       user semantics, MCP guide, research, and roadmap
```

## Evidence rule requirements

Every new rule must include:

1. A narrow claim: exactly what observation the rule supports.
2. At least one positive fixture and one realistic negative fixture.
3. A documented evidence level and confidence.
4. Redaction tests if any response, header, URL, console, or credential-like value is
   handled.
5. A primary source for a CVE or standards claim.

Do not label a size/status heuristic as BOLA, broken access control, sensitive-data
exposure, or a CVE. Strong labels require independent evidence matching that claim.

For `data/cves.go`, catalog-only entries use `Testable: false`. Setting it to true
requires a technique-specific assertion in `internal/exploit`, positive and negative
tests, an affected-version statement, and provenance in
[`data/CVE_PROVENANCE.md`](data/CVE_PROVENANCE.md).

## Safety requirements

- New network execution must have explicit scope, timeout, rate, request-count, and
  response-size controls.
- Active or potentially mutating behavior needs an explicit gate.
- Credentials must be origin-bound and must never appear in output or fixtures.
- MCP gets no arbitrary URL fetch, shell, browser, credentials, or runtime scope
  expansion.
- External references stay disabled until they can use the same policy engine.
- Keep user output schemas backward compatible or introduce a new version.

Security-sensitive architecture changes should explain their threat model in the PR.

## Pull requests

- Open an issue first for major product-direction or schema changes.
- Keep generated binaries and real engagement data out of commits.
- Add a changelog entry for user-visible behavior.
- Complete the PR checklist and state which commands you ran.
- Maintainers may ask for a minimized fixture before accepting a new heuristic.

Good first contributions include parser fixtures from real-world-but-sanitized specs,
false-positive reductions, docs examples, cross-platform tests, and high-confidence
discovery paths.
