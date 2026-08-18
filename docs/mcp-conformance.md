# Airlock MCP conformance contract

This harness-neutral stdio JSON-RPC/MCP surface proposes and observes exact command requests. It never approves or executes them.

## Startup and discovery

```text
airlock mcp --requester-url http://127.0.0.1:8787
```

The endpoint must be HTTP on an explicit IPv4/IPv6 loopback IP and concrete port. Credentials, hostnames, paths, query, fragment, redirects, and environment proxies are refused. `initialize` and `tools/list` work while requester is down and expose exactly `airlock_capabilities`, `airlock_create_request`, and `airlock_requests`.

Schemas are strict JSON objects with `additionalProperties: false`. Failures are sanitized tool results and never echo requester bodies, credentials, trusted paths, raw output, or untrusted URLs. Catalog and receipt text remains hostile data. `github.command/v1` is broad credentialed reviewer-approved RCE, and `executed` is only local-child success—not provider truth.

## Typed inputs

`airlock_capabilities` takes no arguments and returns the current signed catalog projection: profile ID/version, display/authority/sandbox/network/cwd/output labels, bounded argv limits, expiry, and freshness. It does not expose compatibility capabilities.

`airlock_create_request` requires:

```json
{
  "profile_id": "github.command",
  "profile_version": "v1",
  "argv": ["api", "repos/example/project", "--method", "GET"],
  "reason": "Inspect repository metadata",
  "ttl_seconds": 600
}
```

`ttl_seconds` is optional (default 600) and bounded to 60–3600. `argv` has 1–64 distinct ordered elements, at most 4096 bytes each and 32768 bytes total. Shell metacharacters are ordinary argument data. Invalid UTF-8, empty elements, NUL, C0/C1 control or ANSI content, bidirectional Unicode controls, oversized data, unknown fields, and requester attempts to select executable/environment/cwd/credential/identity/timeout/sandbox values fail closed. Reasons are bounded plain text with a defense-in-depth rejection for common credential shapes.

`shell.run/v1` is defined by the protocol vocabulary but disabled and absent from the advertised catalog. MCP must not accept it.

`airlock_requests` takes optional `{ "limit": 1..100, "cursor": "..." }`. Responses contain proposed profile/argv and sanitized signed receipt history with derived freshness/effective state. They contain no resolved executable/config paths, plan body, raw output, environment, credentials, or provider response.

Current objects are `airlock.catalog/v2`, `airlock.request/v2`, and `airlock.receipt/v3`. Readers preserve historical v1 requests, v1 manual receipts, and v2 execution receipts. Current creation against a v1 catalog fails closed.

## Vectors

`internal/mcp/testdata/conformance-vectors.json` is executed by Go tests. It covers valid generic commands, shell metacharacters as argv data, malformed/unknown fields, hostile controls and Unicode, oversize, secret-shaped reasons, expired catalogs, unknown profiles, requester-selected trusted fields, and service unavailability. Harnesses assert result classes rather than server-specific text.
