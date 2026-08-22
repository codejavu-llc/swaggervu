# CVE provenance

SwaggerVu separates a reference catalog from executable verification. An entry is
only `Testable: true` when the browser engine has an independent, marker-based
assertion for that exact vulnerability chain.

| ID | Primary source | SwaggerVu treatment |
|---|---|---|
| CVE-2025-54432 | [GitHub Security Advisory GHSA-qrmm-w75w-3wpx](https://github.com/swagger-api/swagger-ui/security/advisories/GHSA-qrmm-w75w-3wpx) | Testable remote-spec reflected-XSS chain through `url`; requires the SwaggerVu execution canary. |
| CVE-2025-8191 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-8191) | Catalog only. This is specific to macrozheng Mall 1.0.0–1.0.3 and is not generalized to Swagger UI. |
| CVE-2018-25031 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-25031) | Catalog only. Remote-definition spoofing is not presented as proof of XSS. |
| CVE-2016-1000229 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2016-1000229) | Catalog only. The historical key-name technique is not covered by the generic canary. |

Changes to `data/cves.go` must include a primary source, an affected-product
statement, and tests for any executable assertion. See `CONTRIBUTING.md`.
