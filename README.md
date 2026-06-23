<h1 align="center">SwaggerVu</h1>

<p align="center">
  <b>The all-in-one Swagger / OpenAPI discovery, audit &amp; testing toolkit.</b><br>
  Find API docs across thousands of targets, parse any spec, hunt for unauthenticated
  data exposure &amp; secrets, and confirm client-side CVEs with a headless browser —
  in a single static Go binary.
</p>

<p align="center">
  <i>For authorized security testing and bug-bounty use only.</i>
</p>

<p align="center">
  <a href="https://github.com/codejavu-llc/swaggervu/actions/workflows/ci.yml"><img src="https://github.com/codejavu-llc/swaggervu/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/codejavu-llc/swaggervu/releases/latest"><img src="https://img.shields.io/github/v/release/codejavu-llc/swaggervu?color=brightgreen" alt="Latest release"></a>
  <a href="https://goreportcard.com/report/github.com/codejavu-llc/swaggervu"><img src="https://goreportcard.com/badge/github.com/codejavu-llc/swaggervu" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white" alt="Go 1.26">
</p>

---

## Why SwaggerVu

Most Swagger tooling does exactly one thing — brute a path list, *or* parse a spec,
*or* check a single CVE. SwaggerVu fuses the best ideas from across the ecosystem into
one cohesive tool:

| Capability | What it does |
|---|---|
| 🔭 **Discover** | Probe up to thousands of hosts with a curated flagship wordlist, confirm hits with content matchers, and kill false positives with random-path baselining. |
| 🕰️ **Wayback** | Harvest a domain's archived API URLs from the Wayback Machine and feed them straight into discovery — `discover --wayback`. |
| 🛰️ **OSINT** | Find public definitions on SwaggerHub by domain/keyword — `discover --osint`. |
| 🧬 **Detect / Parse** | Identify Swagger 2.0, OpenAPI 3.0 &amp; 3.1 from JSON, YAML, or JS-embedded specs — auto-converting v2→v3. |
| 🎯 **Scan** | Generate one request per operation from the spec, skip `401/403`, and flag endpoints that return data without auth (broken access control / data exposure). |
| 🔑 **Secrets** | Regex corpus (TruffleHog-style + SwaggerSpy) over the spec document and live responses — runs automatically inside `scan` and `all`. |
| 🧪 **Exploit** | Confirm Swagger-UI `configUrl` / `url` DOM XSS and spec-driven HTML injection with a **real headless browser** and screenshot evidence — opt-in &amp; gated. Reads the browser console to distinguish a genuine miss from a **CORS-blocked** PoC fetch, and accepts your own payload host. |
| 🛠️ **Prepare** | Emit ready-to-run `curl` / `sqlmap` commands per endpoint for manual testing — `scan --emit curl\|sqlmap`. |

Built on `kin-openapi` (parsing), `chromedp` (headless confirmation), and a global,
rate-limited worker pool that comfortably handles large target lists.

## Install

**Prebuilt binary (recommended)** — grab the latest static binary for your OS/arch
from the [releases page](https://github.com/codejavu-llc/swaggervu/releases/latest),
no toolchain required.

**From source:**

```bash
go install github.com/codejavu-llc/swaggervu@latest
# or
git clone https://github.com/codejavu-llc/swaggervu && cd swaggervu && go build -o swaggervu .
```

The `exploit` subcommand needs Chrome or Chromium installed (for headless confirmation).

## Demo

> One command, browser-confirmed findings, evidence you can paste straight into a report:
>
> ```bash
> swaggervu all acc.example.com --screenshots ./evidence --md -o report.md
> ```

<!-- TODO: record a demo and embed it here. Suggested:
       asciinema rec demo.cast
       agg demo.cast docs/demo.gif      # https://github.com/asciinema/agg
     then add:  <p align="center"><img src="docs/demo.gif" width="800"></p>  -->


## Autopilot — one command, everything

Give it a domain and it runs the whole chain with **no flags required**: seed from the
Wayback Machine → discover (http+https) → parse → audit endpoints → scan secrets →
confirm client-side CVEs in a headless browser. Every phase is non-destructive.

```bash
# the whole pipeline, every phase, against one domain
swaggervu all acc.example.com

# save a structured report and screenshot evidence of any confirmed CVEs
swaggervu all acc.example.com --json -o report.json --screenshots ./evidence

# or emit a paste-ready Markdown writeup for your bug-bounty submission
swaggervu all acc.example.com --md -o report.md --screenshots ./evidence

# a big list, faster: bump workers + rate; -V logs every probe (not just findings)
swaggervu all -l scope.txt -c 300 --rate 500 -V

# add --risk to also send POST/PUT/PATCH/DELETE (may modify data)
swaggervu all -l scope.txt --risk
```

The only opt-in is `--risk` — destructive HTTP methods are **never** sent without it.
By default the autopilot only logs findings; pass `-V`/`--show-all` to see every probed
request and its status (incl. non-200 and `401`/`403`). Note that non-GET methods are
only generated with `--risk`, so `-V` alone shows `GET` requests.

Wayback seeding runs only for small runs (≤20 targets) — for a big subdomain list it is
skipped (you already have the hosts); run `discover --wayback` on specific hosts if you want it.
The exploit phase confirms with a benign built-in PoC and is skipped gracefully if no
Chrome/Chromium is installed. A run prints a live, phased log and a final summary:

```
phase 1/3 — discovering Swagger/OpenAPI across 1 target(s)
[+] spec: https://acc.example.com/api-doc.json [OpenAPI 3.0] Example API
phase 2/3 — parsing, auditing & secret-scanning 1 spec(s)
[+]   [200] 60711 bytes  GET .../pet/findByStatus?status=available
phase 3/3 — confirming client-side CVEs on 1 candidate(s)
──────── autopilot summary ────────
specs found: 1   interesting endpoints: 4   spec secrets: 0   confirmed exploits: 0
```

## Quick start

```bash
# 1) Discover exposed Swagger/OpenAPI across a list of hosts, save matched paths
swaggervu discover -l targets.txt -c 200 --paths-only -o found.txt

# 2) Same, but strip the domain (path-only wordlist output)
swaggervu discover -l targets.txt --paths-only --no-domain -o paths.txt

# 3) Seed discovery with archived API URLs from the Wayback Machine
swaggervu discover example.com --wayback -o found.txt

# 4) Identify a definition and list its endpoints
swaggervu detect -u https://petstore.swagger.io/v2/swagger.json

# 5) Audit an API for unauthenticated data exposure & secrets
swaggervu scan https://petstore.swagger.io/v2/swagger.json --json -o findings.json
#    ...or a Markdown writeup ready to paste into a report
swaggervu scan https://petstore.swagger.io/v2/swagger.json --md -o findings.md
#    ...auth-aware: probe each endpoint with AND without a token to find
#    broken access control (data the spec says needs auth, but doesn't enforce)
swaggervu scan https://api.example.com/swagger.json --auth 'Authorization: Bearer TOKEN'

# 6) Seed discovery with public specs from SwaggerHub (OSINT)
swaggervu discover example.com --osint

# 7) Confirm Swagger-UI XSS with a headless browser (authorized targets only)
swaggervu discover -l scope.txt --paths-only | swaggervu exploit -l /dev/stdin --confirm --screenshots ./evidence

# 7b) Use your own externally hosted payloads, per param (e.g. surge.sh)
swaggervu exploit $T/swagger-ui --confirm \
  --payload configUrl=https://you.surge.sh/test.json \
  --payload url=https://you.surge.sh/test.yaml
#   confirmation triggers on an alert()/confirm()/prompt() dialog your payload
#   fires, the built-in markers, or a --marker string you know it injects.
```

By default `exploit` injects the bundled hosted PoC specs
(`configUrl` → `https://jumpy-floor.surge.sh/test.json`,
`url` → `https://jumpy-floor.surge.sh/test.yaml`). Override either per param
without touching flags via the environment:

```bash
export SWAGGERVU_PAYLOAD_CONFIGURL=https://your-host.example/test.json
export SWAGGERVU_PAYLOAD_URL=https://your-host.example/test.yaml
```

Or pass `--payload PARAM=URL` per run, `--payload-url URL` for all params, or
`--builtin-payload` to force the self-contained local benign PoC server.

### What `exploit` checks

It tests **2 injection parameters** (`configUrl`, `url`) covering **5 registry entries**
(`swaggervu exploit --list-cves`): **CVE-2025-8191** (configUrl/url DOM XSS via a
DOMPurify ≤2.2.2 bypass — the built-in PoC's nested `math/svg/textarea` payload),
**CVE-2018-25031** (configUrl DOM XSS), **CVE-2016-1000229** (url DOM XSS), and a
generic **spec-driven HTML-injection** check. For each, the headless browser asserts
JS execution (`dom-xss`) or rendered markup (`html-injection`), and classifies every
target as one of:

- `VULNERABLE` — confirmed in the DOM (with screenshot evidence)
- `CORS-BLOCKED` — the UI loaded and fetched the PoC spec, but the browser blocked it
  cross-origin (console shows `blocked by CORS policy`). Re-host the payload with
  `Access-Control-Allow-Origin: *` and retry with `--payload-url` — these are likely leads, not misses.
- `ui-loaded (not injectable)` — swagger-ui rendered but the spec did not inject.

## Discovery output modes

The `discover` command is built for mass scanning and flexible output:

```bash
swaggervu discover -l targets.txt \
  -c 200            # 200 concurrent workers
  --rate 300        # global cap of 300 req/s
  --https-only      # restrict to https (both schemes are probed by default)
  --wayback         # also seed candidates from the Wayback Machine
  --osint           # also seed candidates from SwaggerHub (OSINT)
  --first-only      # stop at the first hit per host (faster)
  --paths-only      # output only matched URLs/paths
  --no-domain       # ...with the domain stripped
  -w custom.txt     # override the built-in wordlist
  --list-paths      # just print the flagship wordlist and exit
```

## Safety &amp; authorization

SwaggerVu is a dual-use security tool. It is **non-destructive by default** across
every command, including the `all` autopilot:

- **Destructive HTTP methods** (`POST`/`PUT`/`PATCH`/`DELETE`) are **never** sent —
  not by `scan`, not by `all` — unless you explicitly pass `--risk`.
- The CVE confirmation in `all` uses a **benign built-in PoC** (a self-contained XSS
  check, no data exfiltrated) and is skipped gracefully when no headless browser is
  available.
- The standalone `exploit` command does nothing without `--confirm` and never silently
  fans out across a target list — use it when you want to drive your own payloads.
- A global `--rate` limiter throttles every module.

Only test systems you own or are explicitly authorized to assess.

## All commands

```
all        Autopilot: one command runs every phase — discover, audit, secrets, exploit
discover   Find exposed Swagger/OpenAPI endpoints (sources: wordlist, --wayback, --osint)
detect     Identify an API definition's type/version and list endpoints
scan       Audit an API: unauth/data-leak + spec & response secrets (--emit curl|sqlmap)
exploit    Confirm Swagger-UI client-side CVEs (gated, headless-confirmed)
```

Five focused commands. Capabilities that used to be their own commands are now
flags on these:

| Old command | Now |
|---|---|
| `wayback <domain>` | `discover <domain> --wayback` |
| `osint <term>` | `discover <term> --osint` |
| `secrets <spec>` | automatic in `scan` (spec document + responses) |
| `prepare <spec>` | `scan <spec> --emit curl\|sqlmap` |

The old names still work (hidden) for script compatibility. Run
`swaggervu <command> --help` for full flags. Global flags (`-c`, `--rate`,
`-t`, `-k`, `--proxy`, `-H`, `-A`, `--random-agent`, `-o`, `--json`, `-q`) apply
to every command.

## Credits

SwaggerVu stands on the shoulders of the tools it learned from — see
[CREDITS.md](CREDITS.md).

## License

MIT. Use responsibly.
