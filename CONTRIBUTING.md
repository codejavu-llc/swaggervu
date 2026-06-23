# Contributing to SwaggerVu

Thanks for helping make SwaggerVu better. Contributions of all sizes are welcome
— a new spec path, a secret regex, a verified CVE, a bug fix, or docs.

## Build & test

```bash
git clone https://github.com/codejavu-llc/swaggervu && cd swaggervu
go build -o swaggervu .
go test ./...
go vet ./...
```

The `exploit` and headless-detection paths need Chrome or Chromium installed.

## Project layout

```
cmd/        cobra subcommands (one file per command)
internal/   engine packages (discover, scan, detect, exploit, secrets, ...)
data/       embedded corpus: paths, secret regexes, content matchers, CVE registry
```

## Easy, high-value contributions

- **Discovery paths** — add real-world spec/UI locations to `data/paths.go`
  (keep the priority-first ordering; entries are deduped automatically).
- **Secret patterns** — add high-signal regexes to `data/regexes.go`. Prefer
  patterns with low false-positive rates; add a test case in
  `internal/secrets/secrets_test.go`.
- **CVE registry** — add to `data/cves.go` **only** entries you have verified
  against a primary source (NVD or a vendor advisory), and wire a real headless
  assertion into `internal/exploit`. We do not ship unverified CVEs.

## Pull requests

- Keep changes focused and run `go test ./...` + `go vet ./...` before opening.
- Match the surrounding code style and comment density.
- For new behavior, add or update a test.

## Scope & safety

SwaggerVu stays **simple, light, and non-destructive by default**. Please don't
add Docker, daemons, heavy dependencies, evasion/anti-detection features, or
mass-targeting helpers. New active capabilities must be opt-in behind a flag.
