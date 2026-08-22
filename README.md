<h1 align="center">SwaggerVu</h1>

<p align="center">
  <strong>Find the OpenAPI. Understand the attack surface. Keep the evidence honest.</strong>
</p>

<p align="center">
  A focused OpenAPI security workbench for researchers—one Go binary, a simple CLI,
  and a policy-bounded MCP server for AI-assisted workflows.
</p>

<p align="center">
  <a href="https://github.com/codejavu-llc/swaggervu/actions/workflows/ci.yml"><img src="https://github.com/codejavu-llc/swaggervu/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/codejavu-llc/swaggervu/actions/workflows/codeql.yml"><img src="https://github.com/codejavu-llc/swaggervu/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://github.com/codejavu-llc/swaggervu/releases/latest"><img src="https://img.shields.io/github/v/release/codejavu-llc/swaggervu?include_prereleases" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
  <img src="https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white" alt="Go 1.26+">
</p>

> Use SwaggerVu only on systems you own or are explicitly authorized to test.

## The 60-second path

```bash
# Install
go install github.com/codejavu-llc/swaggervu@latest

# Inspect a local or remote description—no API operations are executed
swaggervu ./openapi.yaml
swaggervu https://api.example.com/openapi.json

# Give it a host for a bounded HTTPS-only docs check (25 priority paths)
swaggervu api.example.com

# Compare two descriptions
swaggervu diff old.yaml new.yaml

# Review the exact API request plan, then explicitly run it
swaggervu scan ./openapi.yaml --emit curl
swaggervu scan ./openapi.yaml --active --allow-host api.example.com
```

That progression is deliberate: inventory first, plan second, network execution
only after an explicit command and active gate.

## Why researchers use it

| Job | SwaggerVu behavior |
|---|---|
| Find exposed docs | Content-aware discovery with catch-all baselining, priority paths, concurrency, and hard request/body limits. |
| Understand a spec | Swagger 2.0 conversion plus OpenAPI 3.0, 3.1, and 3.2 inventory from JSON, YAML, or common JS embedding. |
| Triage exposure | Endpoint, security-scheme, plaintext-server, server-internal, response, and embedded-secret signals. |
| Compare auth states | Anonymous/authenticated response differentials with credentials bound to an exact origin. |
| Produce useful evidence | Versioned JSON, stable finding IDs, confidence/evidence levels, redacted query values, and Markdown reports. |
| Verify Swagger UI behavior | Explicit headless-browser verification using a local benign canary and an accurately scoped CVE catalog. |
| Work with AI safely | Local stdio MCP with immutable startup scope, budgets, safe roots, DNS defenses, and no browser/shell/auth tools. |

SwaggerVu calls a clue a clue. A large anonymous response is an
`unauthenticated data` signal—not automatically BOLA. An auth comparison is an
`authorization differential`—not proof that another user's object is accessible.
See [Evidence semantics](docs/EVIDENCE.md).

## Commands

```text
swaggervu [target-or-spec]  bounded inspect or local spec inventory
swaggervu discover         find likely OpenAPI descriptions and documentation UIs
swaggervu scan             plan or execute an operation-derived request profile
swaggervu verify           test the supported Swagger UI remote-spec chain
swaggervu diff             compare added/removed operations
swaggervu doctor           check the binary and optional browser support
swaggervu mcp              run the policy-bounded MCP server over stdio
```

`all` remains as a hidden compatibility command. It now requires `--active`, and
its browser phase additionally requires `--verify`. New workflows should compose
the focused commands above.

### Discovery

```bash
swaggervu discover api.example.com
swaggervu discover -l scope.txt --https-only --first-only --paths-only
swaggervu discover example.com --wayback
swaggervu discover example --osint
```

Bare inspection checks HTTPS only and at most 25 priority paths. `discover` is the
explicit full-discovery command. Global controls include `--rate`, `--concurrency`,
`--timeout`, `--max-requests`, `--max-body-mb`, `--allow-host`, and
`--allow-private`.

### Scan and auth comparison

```bash
# Print only; no API operation is sent
swaggervu scan openapi.yaml --emit curl

# Execute GET/HEAD operations within one exact hostname
swaggervu scan openapi.yaml --active --allow-host api.example.com --max-requests 100

# Compare anonymous and authenticated responses. The credential can only go to
# this exact scheme + host + port.
swaggervu scan openapi.yaml --active \
  --allow-host api.example.com \
  --auth-origin https://api.example.com \
  --auth 'Authorization: Bearer REDACTED'

# Non-GET/HEAD operations need both gates
swaggervu scan openapi.yaml --active --risk --allow-host api.example.com
```

Sensitive `-H` and `--auth` values are refused without `--auth-origin`. Redirects
are same-origin only, private/special-use addresses are denied by default, external
spec references are disabled, and report files are created with owner-only mode.

### Browser verification

```bash
swaggervu verify https://docs.example.com/swagger-ui/ \
  --active --screenshots ./evidence
```

Chrome or Chromium is optional and used only for browser-backed paths. The default
payload is served locally for the duration of the process; SwaggerVu does not rely
on a third-party payload host. Ambient dialogs do not count as evidence. Use
`swaggervu verify --list-cves` and see [CVE provenance](data/CVE_PROVENANCE.md) for
the exact catalog/testability boundary.

## MCP for AI-assisted research

Start with authority fixed on the command line:

```bash
# Local descriptions only; inspection/audit tools, no network execution
swaggervu mcp --allow-root /absolute/path/to/specs

# Permit one public hostname and the bounded GET/HEAD scan tool
swaggervu mcp --allow-host api.example.com --active \
  --max-requests 100 --max-body-mb 2 --rate 5
```

Example client configuration:

```json
{
  "mcpServers": {
    "swaggervu": {
      "command": "/absolute/path/to/swaggervu",
      "args": ["mcp", "--allow-root", "/absolute/path/to/specs"]
    }
  }
}
```

The seven tools are `inspect_spec`, `audit_spec`, `discover_docs`, `plan_scan`,
`run_readonly_scan`, `get_finding`, and `render_report`. The network scan tool is
intentionally not annotated read-only: GET/HEAD are read-intent, but APIs can have
side effects. MCP exposes no arbitrary shell, browser verification, credentials,
Wayback, or unbounded URL-fetch tool. Full setup and threat model:
[docs/MCP.md](docs/MCP.md).

## Install and verify

Prebuilt Linux, macOS, and Windows archives are published on the
[releases page](https://github.com/codejavu-llc/swaggervu/releases). Releases include
checksums, Syft-generated SBOMs, and GitHub build-provenance attestations.

```bash
# Source install (Go 1.26+)
go install github.com/codejavu-llc/swaggervu@latest

# Verify a downloaded release after `gh auth login`
gh attestation verify swaggervu_*.tar.gz --repo codejavu-llc/swaggervu
sha256sum -c checksums.txt
```

Run `swaggervu doctor` after installation.

## Project principles

- Simple first run; expert controls remain available.
- No vulnerability label without matching evidence.
- Secrets and query values do not belong in logs or reports.
- Network authority is explicit, origin-bound, and budgeted.
- AI integration receives less authority than a human CLI session.
- Rules and CVEs need primary-source provenance and regression tests.

The research and roadmap behind these choices are in
[docs/PRODUCT_PLAN.md](docs/PRODUCT_PLAN.md). Contributions, new fixtures, false
positive reports, and research-backed rules are welcome—start with
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). Use responsibly.
