# MVP context map

The Airlock MVP is one Go binary deployed in two roles. The requester owns no
human credentials. The trusted role owns the signing key and human-side
adapter policy, initiates all cross-node traffic, and never executes provider
commands.

| Concept | Implementation | Executable evidence |
| --- | --- | --- |
| Canonical signed objects | `internal/model` | digest, signature, expiry, mutation, and transition tests |
| Local configuration and adapter constraints | `internal/config` | strict JSON decoding and model validation |
| Private keys | `internal/keys` | exclusive creation, strict private-key modes, no-overwrite tests |
| Atomic durable state | `internal/statefile` | owner-only files, directory and symlink tests |
| Loopback boundary | `internal/netguard` | default loopback and non-loopback-refusal test |
| Requester catalog/request/receipt state | `internal/requester` | store lifecycle, bounded request-page, and read-only HTTP/UI tests |
| Harness-neutral typed MCP bridge | `internal/mcp`, `internal/requester/client.go` | offline initialization/tool registration, strict schemas, loopback transport, and conformance vectors |
| Trusted GitHub adapter and review state | `internal/trusted/adapter.go`, `internal/trusted/store.go` | hostile argument, immutable display, replay, and receipt-binding tests |
| Trusted outbound polling | `internal/trusted/sync.go` | in-process end-to-end HTTP transport test and local smoke |
| Trusted identity and decision UI | `internal/trusted/server.go` | allowlist, dev/prod identity, CSRF, and method tests |
| CLI and process lifecycle | `cmd/airlock` | `go vet`, build through smoke, signal-aware HTTP shutdown |
| Deployment | `configs`, `deploy/systemd`, `docs/deployment.md` | example configs plus local smoke |

The provider boundary is intentionally outside the binary. The adapter emits
one validated `gh api` command as text for a human to copy. There is no shell,
browser, `gh`, provider SDK, or generic command execution package in the
runtime.
