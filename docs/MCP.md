# SwaggerVu MCP server

SwaggerVu ships a local Model Context Protocol server over stdio. It is designed for
AI-assisted description inventory and tightly bounded research—not autonomous,
general-purpose scanning.

## Start with immutable authority

The server refuses to start without at least one allowed hostname or filesystem root.
Authority cannot be expanded by a model tool call.

```bash
# Offline/local-spec workflow
swaggervu mcp \
  --allow-root /absolute/path/to/specs \
  --max-body-mb 2

# One-host workflow with read-intent API operations enabled
swaggervu mcp \
  --allow-host api.example.com \
  --active \
  --max-requests 100 \
  --max-body-mb 2 \
  --rate 5 \
  --timeout 15
```

Private, loopback, link-local, documentation, benchmarking, multicast, and other
special-use address ranges are denied unless the operator explicitly adds
`--allow-private`. Use that flag only for an authorized internal assessment.

## Client configuration

Most clients accept this shape (the enclosing settings filename varies by client):

```json
{
  "mcpServers": {
    "swaggervu": {
      "command": "/absolute/path/to/swaggervu",
      "args": [
        "mcp",
        "--allow-root",
        "/absolute/path/to/specs"
      ]
    }
  }
}
```

Use absolute paths. SwaggerVu reserves stdout for MCP protocol frames; errors remain
on stderr. Restart the server to change scope or enable active operations.

## Tools

| Tool | Network/API operations | Purpose |
|---|---:|---|
| `inspect_spec` | Only if source is an allowed URL | Parse and inventory endpoints/security schemes. |
| `audit_spec` | Only if source is an allowed URL | Inventory plus redacted embedded-secret signals. |
| `discover_docs` | Yes, bounded to 25 priority paths | Find likely docs on one allowlisted host. |
| `plan_scan` | Only to load an allowed remote spec | Return the exact GET/HEAD request plan; sends no API operations. |
| `run_readonly_scan` | Yes; startup `--active` required | Execute the bounded GET/HEAD profile and store interesting evidence. |
| `get_finding` | No | Retrieve one sanitized finding minted by this server process. |
| `render_report` | No | Render sanitized Markdown for a completed run ID. |

The name `run_readonly_scan` is retained for clarity with existing MCP conventions,
but its tool annotation is deliberately **not** read-only. GET and HEAD express read
intent; poorly designed APIs can still mutate state.

Resources expose the immutable startup policy, a finding-schema summary, and the rule
catalog. The canonical schemas are in [`schemas/`](../schemas/).

## Enforcement model

- Exact hostname allowlist for every request.
- DNS resolution validation before requests and again at dial time to resist rebinding.
- Same-origin redirects only, with a ten-hop cap.
- Shared process-wide request budget, rate limit, timeout, and response-body limit.
- Filesystem authorization after absolute-path and symlink resolution.
- External OpenAPI references disabled.
- No arbitrary request headers or credentials in tool arguments.
- No shell, browser verification, custom payload, Wayback, SwaggerHub OSINT, or proxy
  capability in MCP.
- Finding/run IDs are server-minted and stored only in memory.

The serialized startup policy follows
[`mcp-policy-v1.schema.json`](../schemas/mcp-policy-v1.schema.json).

## Threat model

OpenAPI titles, descriptions, examples, operation names, remote responses, and tool
results are untrusted content. A description can contain prompt injection just as it
can contain malicious HTML. The MCP server returns structured data but cannot force a
client or model to reason safely about that data.

For sensitive engagements:

1. Prefer a local spec and `--allow-root` with no network host.
2. Start without `--active`; inspect and review `plan_scan` first.
3. Use the smallest hostname set and request budget.
4. Keep credentials outside the MCP session.
5. Review findings manually before reporting or acting.

These controls follow the direction of the MCP specification's
[security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices): minimize authority, validate inputs, and avoid confused-deputy flows.
