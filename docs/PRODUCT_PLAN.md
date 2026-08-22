# SwaggerVu product and execution plan

Status: proposed execution contract  
Audit date: 2026-08-22  
Repository: <https://github.com/codejavu-llc/swaggervu>

## Product thesis

SwaggerVu should be the fastest trustworthy path from a domain or API
description to:

1. a scoped API inventory,
2. defensible security signals,
3. sanitized evidence that another researcher can replay.

The product wins on clarity, evidence quality, and a small binary—not by trying
to replace full fuzzers, intercepting proxies, or enterprise API platforms.

The one-line experience should be:

```bash
swaggervu api.example.com
swaggervu openapi.yaml
```

SwaggerVu should infer whether the input is a host, docs URL, spec URL, or local
file. A bare invocation performs bounded discovery and static inspection. It
must print a request budget before network work and must not execute operations
from a discovered spec, contact historical/OSINT services, launch a browser PoC,
or use mutating methods unless the operator selects an explicit mode.

## Product principles

- Evidence before labels. Severity and confidence are separate fields.
- Safe means bounded and explained, not a blanket claim that GET is harmless.
- No credentials, tokens, or raw secret matches in normal output.
- Scope is an enforceable runtime policy, not a disclaimer.
- Every network request has an origin, reason, budget, and redirect policy.
- A failed check means “not observed,” never “not vulnerable.”
- AI receives less ambient authority than a human CLI operator.
- One binary, useful offline, scriptable stdout, stable structured output.
- Integrate with specialist tools instead of cloning their deepest features.

## Audit findings that block the next stable release

These are release blockers, not backlog polish.

1. `all` automatically launches the browser verification phase without the
   explicit confirmation required by the standalone `exploit` command.
2. Default browser payloads use third-party Surge URLs while command text calls
   them local, built-in, and self-contained.
3. The headless exploit engine always ignores TLS certificate errors.
4. Any JavaScript dialog on the page can become proof of injected script, even
   when the dialog is unrelated to SwaggerVu's canary.
5. One generic payload result is attributed to every CVE sharing a query
   parameter rather than proving each vulnerability independently.
6. The CVE registry contains materially inaccurate claims:
   - CVE-2025-8191 concerns macrozheng Mall through 1.0.3, not a general Swagger
     UI 3.14.1–3.37.x version range.
   - CVE-2018-25031 is a remote-definition spoofing/phishing issue, not the
     generic DOM-XSS claim currently reported.
   - the Swagger UI advisory identifies the older remote-spec XSS chain as
     CVE-2025-54432.
   - `CVE-2025-8191-url` is not a CVE identifier and must never be presented as
     one.
7. Secret findings preserve and print the matched credential value in console,
   JSON, and Markdown reports.
8. A successful anonymous response of only 256 bytes can become
   “unauthenticated data”; an auth-vs-anonymous comparison can become “broken
   access control.” Neither proves BOLA, which requires an object and ownership
   or role boundary.
9. Global and authenticated headers can be sent to server URLs selected by an
   untrusted API description. Origin binding is not enforced.
10. Redirects and browser subresources are not constrained to the operator's
    scope. MCP would turn this into an SSRF/confused-deputy risk.
11. OpenAPI security sections are deleted during relaxed parsing, discarding
    data that the authorization analysis needs.
12. OpenAPI 3.2 is classified as 3.0, while 3.2 is now the current published
    specification. The current parser dependency is also behind its latest
    release.
13. Browser, exploit, HTTP client, output, OSINT, and Wayback paths have no test
    coverage. Scanner statement coverage is 17.4% and command coverage is 14.8%.
14. Local verification is currently affected by an inconsistent Go toolchain
    installation (`go1.26.0` packages versus a reported `go1.26.3` tool). The
    last public CI run is green, but local release verification is not credible
    until the environment is repaired.
15. The public repository has no protected default branch, no Dependabot or
    secret protection enabled, no CodeQL setup, no issue/PR templates, and no
    release provenance, SBOM, or signatures.

## Deliberately small CLI

### Public command surface

```text
swaggervu <target-or-spec>       bounded discover + offline inspect
swaggervu scan <spec-or-url>     execute a declared request profile
swaggervu verify <swagger-ui>    controlled browser verification
swaggervu diff <old> <new>       security-relevant contract change
swaggervu mcp                    local MCP server
```

`discover`, `detect`, `all`, and `exploit` remain as deprecated aliases for one
compatibility cycle. Old invocations must receive an exact replacement command.

### Modes and consent

| Mode | Network behavior | Requirement |
|---|---|---|
| `inspect` | Local file only, or bounded docs/spec GETs for a supplied host | Default |
| `read-only` | Declared GET/HEAD operations, bounded to allowed origins | `--active` |
| `workflow` | Stateful calls described by an approved workflow | `--active --workflow-policy FILE` |
| `mutating` | POST/PUT/PATCH/DELETE or operation with unknown semantics | `--active --allow-method ...` |
| `browser` | Loads a UI and local canary in Chromium | `verify --active` |

HTTP method alone does not establish safety. Profiles also constrain operation
IDs, paths, request count, rate, body size, redirects, and target origins.

### Configuration

Use one optional `.swaggervu.yaml` with a published JSON Schema. Command-line
flags override it. Authentication comes from named local profiles or environment
references; tokens are never placed directly in the config file or accepted as
MCP model arguments.

Example:

```yaml
version: 1
scope:
  hosts: [api.example.com]
  include_subdomains: false
  allow_private_networks: false
network:
  max_requests: 200
  rate: 10
  redirects: same-origin
auth:
  profile: researcher-a
```

## Finding and evidence contract

Every finding receives a stable fingerprint and this minimum schema:

```text
schema_version, finding_id, rule_id, title, category
severity, confidence, evidence_level, status
target_origin, operation_id, method, path_template
observed_at, request_summary, response_summary
redactions, replay, references, limitations
```

### Evidence levels

| Level | Meaning | Example |
|---|---|---|
| `inventory` | Fact read from a spec or page | Public server URL or missing security declaration |
| `signal` | Heuristic that needs review | Anonymous 200 with a structured body |
| `differential` | Controlled comparison changed behavior | anonymous vs profile A response differs |
| `verified` | Scanner-owned canary or exact assertion succeeded | tagged UI canary executed |
| `confirmed` | Ownership/role boundary and impact are demonstrated | profile B reads profile A's object |

BOLA is never emitted below `confirmed`. It requires at least two principals or
an anonymous/owned-object boundary, a known object identifier, ownership
metadata, and a successful cross-boundary replay. Anonymous availability alone
is a signal or, where the spec declares auth, an authorization differential.

### Secret handling

- Default output: type, source location, length, and a keyed fingerprint.
- Optional preview: at most the first 3 and last 2 characters, when safe.
- Query strings and authorization/cookie headers are redacted everywhere.
- Raw values are kept only in an explicitly requested local evidence vault with
  owner-only permissions and a warning.
- Markdown, JSON, MCP, CI annotations, screenshots, and logs never reveal raw
  values.

### Machine interfaces

- Versioned JSON and JSONL schemas.
- Deterministic exit codes: operational error, findings at threshold, partial
  run, policy refusal, and success.
- SARIF only for source-addressable/static findings; runtime HTTP observations
  remain in SwaggerVu JSON to avoid pretending they map to source lines.
- Sanitized curl replay with placeholders; never default to `-k`.

## Architecture direction

### Parsing decision gate

Run a fixture-based spike comparing current `kin-openapi` with `libopenapi`.
`libopenapi` is the leading candidate because it supports OpenAPI 3.2, 3.1,
3.0, Swagger, Overlay 1.1, and Arazzo 1.1 in Go. Migration is accepted only if
it passes the corpus with equal or better memory, parse success, reference
safety, and normalized operation output.

External references are disabled by default for remote/untrusted descriptions.
When enabled, they must obey the same host allowlist, DNS/IP validation,
redirect checks, byte budget, depth limit, cycle detection, and content-type
rules as all other network fetches.

### Engine boundaries

```text
input classifier
  -> scope/policy compiler
  -> fetcher (all network enforcement)
  -> parser + immutable normalized inventory
  -> rules (offline facts/signals)
  -> executor (explicit request profile)
  -> evidence/redaction pipeline
  -> CLI / JSON / Markdown / MCP adapters
```

No command or MCP handler creates its own HTTP client. Browser navigation,
subresources, redirects, spec servers, `$ref` targets, Wayback, and SwaggerHub
all pass through policy-aware boundaries or remain disabled.

### Specialist-tool interoperability

SwaggerVu should export clean inputs and evidence rather than absorb every
engine:

- Schemathesis: generated config and sanitized auth placeholders for
  property-based and stateful testing.
- RESTler: normalized spec plus dictionary/workflow hints for deep stateful
  fuzzing.
- ZAP/Burp: HAR and request collections for proxy-led manual assessment.
- oasdiff/openapi-changes: contract-diff interoperability rather than a second
  incompatible diff format.
- Arazzo: explicit multi-step workflows and data dependencies in a later phase.

## MCP design

### First release boundary

Ship `swaggervu mcp` over local stdio using the official Go SDK v1.7.x, which
supports MCP revision `2026-07-28` while retaining older-client compatibility.
Do not ship unauthenticated remote HTTP transport in the first release. Stdio
keeps the connection local and avoids inventing an OAuth/service deployment
story before it is needed.

The operator fixes authority at process startup:

```bash
swaggervu mcp \
  --allow-host api.example.com \
  --mode inspect \
  --max-requests 100 \
  --rate 5
```

The model cannot widen hosts, enable private networks, add credentials, change
methods, disable TLS, increase budgets, or enable browser verification through
tool arguments.

### Initial tools

| Tool | Purpose | Default annotations |
|---|---|---|
| `inspect_spec` | Parse and inventory a local file or allowlisted spec URL | read-only; open-world only for URL |
| `audit_spec` | Run offline security/configuration rules | read-only; closed-world |
| `discover_docs` | Bounded high-confidence docs/spec discovery | read-only intent; open-world |
| `plan_scan` | Return exact operations, hosts, methods, and budget without sending | read-only; closed-world |
| `run_readonly_scan` | Execute the startup-approved GET/HEAD profile | non-destructive intent; open-world |
| `get_finding` | Retrieve one sanitized finding and replay recipe by ID | read-only; closed-world |
| `render_report` | Render sanitized Markdown/JSON from a completed run | read-only; closed-world |

Do not expose mutating methods, generic arbitrary-URL fetch, browser exploit,
shell commands, raw headers, raw secrets, Wayback, or SwaggerHub in MCP v1.

MCP tool annotations are descriptive hints, not security controls. Each handler
must execute the compiled operator policy again. Network tools return their
resolved IPs, redirects, request count, truncation, and policy decisions.

### Resources

```text
swaggervu://policy
swaggervu://runs/{run_id}/summary
swaggervu://runs/{run_id}/findings
swaggervu://findings/{finding_id}
swaggervu://catalog/rules
swaggervu://schemas/finding-v1
```

Resources are bounded, paginated, and sanitized. Run state uses explicit
server-minted IDs, matching the stateless MCP 2026-07-28 model.

### Prompts

Prompts are optional convenience templates, never authorization:

- `review_api_description`: explain an offline inventory and prioritize signals.
- `prepare_authorized_assessment`: gather scope and produce a scan plan.
- `triage_findings`: separate verified results from signals and draft a report.

### MCP security tests

- public host that resolves or rebinds to loopback/private/link-local is denied,
- every redirect and subresource is revalidated,
- URL userinfo and non-HTTP schemes are denied,
- auth profile is origin-bound and stripped on cross-origin transitions,
- startup scope cannot be widened by any tool call,
- request/byte/time budgets are atomic across concurrent calls,
- tool output cannot include raw credentials or unbounded response bodies,
- cancellation stops queued and in-flight work,
- stdout contains protocol frames only; logs go to stderr,
- protocol conformance covers current and supported legacy clients.

Publish to the official MCP Registry only after conformance, security, and clean
installation tests pass for the release artifact.

## Execution roadmap

### Phase 0 — restore trust

- Remove third-party payload defaults; use only the local tagged canary.
- Make all browser checks explicit and remove them from the default `all` path.
- Honor TLS verification by default in every engine.
- Require scanner-owned markers for every browser assertion.
- Correct/rebuild the CVE catalog from primary advisories; assert one advisory
  and one technique per check.
- Redact secrets and sensitive URL/header data at the data model boundary.
- Replace vulnerability labels produced by response-size heuristics with the
  evidence model.
- Bind credentials and redirects to approved origins.
- Add response, reference, depth, request, and time budgets.
- Repair the Go toolchain and pin a supported Go patch release in CI.

Release gate: no known path can auto-run browser payloads, reveal a fixture
secret, send auth to another origin, ignore TLS implicitly, or claim a CVE from
an unrelated canary.

### Phase 1 — one-command public preview

- Implement input classification and bare invocation.
- Add the policy compiler and a single policy-aware fetcher.
- Add a high-confidence quick discovery set and keep full discovery explicit.
- Introduce versioned finding/report schemas and deterministic exit codes.
- Add `doctor`, shell completion docs, copy-paste installs, and migration help.
- Build a deterministic fixture lab covering Swagger 2.0 and OpenAPI 3.0, 3.1,
  and 3.2, JSON/YAML/JS UI embedding, redirects, TLS, auth, CSP/CORS, ambient
  dialogs, false-positive pages, cyclic/remote refs, and oversized inputs.

Release gate: a new user can install and obtain a useful redacted result with
one command; the benchmark corpus meets published precision/recall and request
budget targets; macOS/Linux/Windows smoke tests pass.

### Phase 2 — AI-native local MCP

- Implement the stdio server and initial tools/resources.
- Add MCP conformance, policy, concurrency, cancellation, redaction, and
  adversarial SSRF tests.
- Add configuration snippets for major MCP clients and a five-minute tutorial.
- Dogfood the same service layer from CLI and MCP; no duplicated scanner logic.

Release gate: MCP cannot exceed startup authority in the adversarial suite,
all tool results validate against output schemas, and an AI client can inspect a
fixture API end-to-end without seeing a raw secret.

### Phase 3 — researcher workflows

- Named auth profiles with refresh hooks and strict origin binding.
- Two-principal authorization matrices and owned-object BOLA confirmation.
- Arazzo 1.1 import/export for explicit stateful workflows.
- HAR/Burp/ZAP import/export and sanitized replay bundles.
- Contract/security diff using a proven library or interoperable format.
- Adapters for Schemathesis and RESTler.

Release gate: every confirmed access-control result has a replayable role/object
boundary; created test data has recorded cleanup or an explicit residue warning.

### Phase 4 — community platform, without bloat

- Versioned declarative rule packs with JSON Schema and fixture requirements.
- Rule provenance, license, primary reference, expected evidence level, and
  false-positive notes are mandatory.
- Signed community pack index; no arbitrary code plugins in the default binary.
- Public benchmark repository and regression submissions.
- MCP Registry publication and optional remote deployment design only after a
  threat model and OAuth implementation review.

Release gate: every bundled/community rule passes positive, negative, and
redaction fixtures; pack updates are reproducible and signature-verifiable.

## GitHub and release readiness

- Protect `main`: required CI/security checks, reviewed PRs, no force pushes.
- Enable Dependabot alerts/updates, secret scanning/push protection, and CodeQL.
- Add Dependabot config, `govulncheck`, license/provenance checks, fuzz tests,
  and pinned GitHub Action SHAs.
- Add issue forms for bug, false positive, rule proposal, and docs; private
  vulnerability contact; PR template; CODEOWNERS; code of conduct; support doc.
- Disable the unused wiki and enable Discussions when there is a moderation
  owner and seeded categories.
- Publish SBOMs, checksums, build provenance attestations, and signatures for
  every archive. Document verification commands next to installation.
- Add Homebrew/Scoop packages only after artifact verification is automated.
- Audit the copied/reimplemented path, matcher, regex, and CVE corpora against
  upstream licenses and add machine-readable provenance.
- Use a release candidate before the next stable tag. Do not call Phase 0/1
  output “stable” while the evidence schema is still changing.

## Public quality scorecard

Publish these values per release so “best” stays falsifiable:

- discovery precision and recall on the fixture corpus,
- false-positive rate by rule,
- supported spec/version fixtures,
- p50/p95 runtime and peak memory for small/large specs,
- requests sent versus declared budget,
- redaction leak tests passed,
- MCP conformance and adversarial policy tests passed,
- packages with direct tests and statement coverage,
- unresolved confirmed defects and security advisories,
- artifact verification status for every platform.

Stars and download counts are community feedback, not quality gates.

## Research basis

- OpenAPI 3.2.0: <https://spec.openapis.org/oas/latest.html>
- Arazzo 1.1.0: <https://spec.openapis.org/arazzo/latest.html>
- Overlay 1.1.0: <https://spec.openapis.org/overlay/latest.html>
- OWASP API1 BOLA: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
- OWASP API5 BFLA: <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>
- Swagger UI remote-definition advisory: <https://github.com/swagger-api/swagger-ui/security/advisories/GHSA-qrmm-w75w-3wpx>
- NVD CVE-2025-8191: <https://nvd.nist.gov/vuln/detail/CVE-2025-8191>
- NVD CVE-2018-25031: <https://nvd.nist.gov/vuln/detail/CVE-2018-25031>
- NVD CVE-2016-1000229: <https://nvd.nist.gov/vuln/detail/CVE-2016-1000229>
- MCP 2026-07-28 security practices: <https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tutorials/security/security_best_practices.mdx>
- Official MCP Go SDK: <https://github.com/modelcontextprotocol/go-sdk>
- MCP tool annotations schema: <https://modelcontextprotocol.io/specification/2025-11-25/schema>
- Official MCP Registry: <https://github.com/modelcontextprotocol/registry>
- Schemathesis architecture: <https://github.com/schemathesis/schemathesis/blob/master/ARCHITECTURE.md>
- RESTler: <https://github.com/microsoft/restler-fuzzer>
- ZAP OpenAPI support: <https://www.zaproxy.org/docs/desktop/addons/openapi-support/>
- oasdiff breaking changes: <https://github.com/oasdiff/oasdiff/blob/main/docs/BREAKING-CHANGES.md>
- libopenapi: <https://github.com/pb33f/libopenapi>
- GitHub artifact attestations: <https://docs.github.com/en/actions/concepts/security/artifact-attestations>

