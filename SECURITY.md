# Security Policy

## Responsible use

SwaggerVu is a **dual-use security tool** intended for **authorized** security
testing and bug-bounty research only. By using it you confirm that you have
explicit permission to test every target you supply.

SwaggerVu is non-destructive by default:

- Destructive HTTP methods (`POST`/`PUT`/`PATCH`/`DELETE`) are **never** sent
  unless you explicitly pass `--risk`.
- The `exploit` module is gated behind `--confirm` and never silently fans out
  across a target list.
- A global `--rate` limiter throttles every module.

Do **not** use this tool against systems you do not own or are not authorized to
assess. Misuse may be illegal.

## Reporting a vulnerability

If you find a security issue **in SwaggerVu itself** (not in a target you
scanned), please report it privately:

- Open a [GitHub Security Advisory](https://github.com/codejavu-llc/swaggervu/security/advisories/new), or
- Email the maintainers (see repository profile).

Please do not open a public issue for security-sensitive reports. We aim to
acknowledge reports within a few days.

## Supported versions

The latest released version is supported. Fixes land on `main` and ship in the
next tagged release.
