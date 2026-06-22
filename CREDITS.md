# Credits

SwaggerVu is an original Go tool, but its capabilities were informed by studying
and re-implementing the best ideas from these excellent open-source projects.
Huge thanks to their authors.

| Project | Author | Ideas adopted |
|---|---|---|
| [sj (Swagger Jacker)](https://github.com/BishopFox/sj) | BishopFox | Schema→example request-generation engine, Swagger 2.0→3.x conversion via `kin-openapi`, JS-bundle spec unwrapping, dangerous-verb guardrails, `prepare` → curl/sqlmap templates, priority path lists. |
| [autoswagger](https://github.com/intruder-io/autoswagger) | Intruder | Skip-`401/403` access-control logic, largest-response BOLA heuristic, basepath fallback, TruffleHog-style secret regexes, multi-style path placeholders, mass-concurrency model. |
| [apidetector](https://github.com/brinhosa/apidetector) | brinhosa | Random-path + similarity error-baselining for false-positive suppression, broad endpoint path list, headless XSS PoC pattern. |
| [SwaggerSpy](https://github.com/UndeadSec/SwaggerSpy) | UndeadSec | SwaggerHub `apiproxy/specs` OSINT discovery + pagination, secret-regex corpus. |
| [swagger-ez](https://github.com/RhinoSecurityLabs/swagger-ez) | Rhino Security Labs | Spec-wide parameter handling and schema auto-sampling concepts. |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | ProjectDiscovery | `swagger-api.yaml` path list and content-confirmation matchers. |

### Libraries

- [getkin/kin-openapi](https://github.com/getkin/kin-openapi) — OpenAPI parsing &amp; v2→v3 conversion
- [chromedp/chromedp](https://github.com/chromedp/chromedp) — headless-browser confirmation
- [spf13/cobra](https://github.com/spf13/cobra) — CLI framework

If your project should be credited here and isn't, please open an issue.
