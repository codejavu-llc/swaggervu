# Security policy

## Supported versions

The latest stable release and the current release candidate are supported. Security
fixes land on `main` and are released as quickly as practical.

## Report a vulnerability privately

Please do not open a public issue for a vulnerability in SwaggerVu itself.

- Preferred: [open a private GitHub Security Advisory](https://github.com/codejavu-llc/swaggervu/security/advisories/new).
- If GitHub advisories are unavailable, contact the maintainers through the Codejavu
  organization profile and ask for a private reporting channel. Do not include exploit
  details in the first public message.

Include the affected version/commit, operating system, minimal reproduction, impact,
and any suggested remediation. Remove real target credentials and data.

We aim to acknowledge a complete report within three business days, provide an initial
assessment within seven, and coordinate disclosure after a fix is available. Complex
issues may take longer; we will keep the reporter informed.

## Security boundaries

SwaggerVu is a dual-use tool for explicitly authorized research. Its controls reduce
accidents; they do not create authorization.

- Bare-host mode performs a bounded HTTPS-only documentation check.
- `scan` requires `--active`; non-GET/HEAD methods additionally require `--risk`.
- `verify` requires `--active` (legacy `--confirm` remains accepted).
- The legacy `all` command requires `--active`; browser work also needs `--verify`.
- Sensitive headers require an exact `--auth-origin`.
- Private/special-use networks require `--allow-private`.
- Output URLs, secret matches, and browser console data cross a redaction boundary.
- MCP scope and budgets are fixed at startup; MCP accepts no credentials or shell work.

GET and HEAD are read-intent, not a guarantee of no side effects. Custom specs can
generate surprising paths and values. Always inspect `scan --emit curl`, use a staging
environment when possible, and choose a hard `--max-requests` budget.

See [evidence semantics](docs/EVIDENCE.md) and the [MCP threat model](docs/MCP.md).

## Release integrity

Tagged releases are built by GitHub Actions with pinned action revisions. Release
archives include SHA-256 checksums and SBOMs and receive GitHub artifact attestations.
Consumers can verify them with:

```bash
gh attestation verify <archive> --repo codejavu-llc/swaggervu
sha256sum -c checksums.txt
```
