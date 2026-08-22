## What changed

<!-- Explain the user/researcher problem and the chosen change. -->

## Evidence and safety

- [ ] Claims match the evidence level; heuristics are not presented as confirmed vulnerabilities.
- [ ] Network changes have scope, timeout, rate, request-count, and body-size controls.
- [ ] Output containing URLs, headers, responses, secrets, or browser data crosses the redaction boundary.
- [ ] CVE/rule changes include a primary source, positive fixture, and realistic negative fixture.
- [ ] MCP changes do not expand authority at runtime.
- [ ] User-visible behavior is documented and added to `CHANGELOG.md`.

## Validation

- [ ] `gofmt -w .`
- [ ] `go vet ./...`
- [ ] `go test -race ./...`
- [ ] I did not commit credentials, real engagement data, generated binaries, or screenshots.

<!-- Add any extra test commands and sanitized reproduction details. -->
