# Evidence semantics

SwaggerVu is an evidence collector, not an automatic vulnerability adjudicator.
Its labels describe what was observed and how strongly the observation supports a
security hypothesis.

## Levels

| Level | Meaning | Typical examples |
|---|---|---|
| `signal` | One observation worth review. Alternate explanations are likely. | Anonymous 200 response over the size threshold; possible embedded secret; server error signature. |
| `differential` | Two controlled observations differ in a security-relevant way. | A spec-declared protected operation returns usable content anonymously; anonymous/authenticated bodies are invariant. |
| `confirmed` | An independent assertion demonstrated the exact behavior. | SwaggerVu's tagged browser canary executed through the tested remote-spec vector. |

`confidence` (`low`, `medium`, `high`) describes confidence in the observation.
`severity` describes plausible impact if the observation is valid. Neither replaces
researcher review.

## What findings do not claim

- `unauthenticated data` does not by itself mean sensitive data, missing auth, or
  Broken Object Level Authorization (BOLA).
- `authorization differential` does not prove cross-user object access. Confirming
  BOLA requires controlled principals, object ownership, and an unauthorized access
  result.
- `authentication invariant` can be correct for a deliberately public operation.
- A regex secret signal can be a test value or false positive. SwaggerVu never emits
  the matched value.
- Loading remote HTML is not XSS. A CVE is attached only when the verifier's tagged
  assertion matches the cataloged technique.

## Finding identity and schema

Network findings use `schema_version: swaggervu.finding/v1` and an `sv-…` ID derived
from the sanitized method, URL, and reasons. This makes the identity deterministic
for the same observation while excluding response bodies and credentials. The
machine-readable contract is [finding-v1.schema.json](../schemas/finding-v1.schema.json).

New output contracts will use a new schema version rather than silently changing v1.

## Redaction boundary

Before output is logged, serialized, returned over MCP, or rendered into Markdown:

- URL userinfo is removed.
- Every query value becomes `[VALUE]`; credential-like keys become `[REDACTED]`.
- Sensitive header values are never rendered.
- Secret matches become a process-local HMAC fingerprint plus byte length. The key
  is random per process, so a fingerprint cannot be correlated across separate runs.
- Browser console messages are used in-process for classification and not serialized.
- Report and screenshot files use owner-only permissions where supported.

If you discover a redaction bypass, report it privately using the process in
[SECURITY.md](../SECURITY.md).

## Reporting a real issue

A high-quality researcher report should add the context SwaggerVu intentionally does
not infer: authorization scope, object ownership, data sensitivity, reproduction
conditions, and demonstrated impact. Treat generated curl commands as a starting
point and review all placeholders before use.
