# MVP context map

The Airlock MVP is one Go binary deployed in two roles. The requester owns no
human credentials. The trusted role owns the signing key and human-side
adapter policy, initiates all cross-node traffic, and can execute only one
locally reconstructed GitHub plan after trusted human approval.

| Concept | Implementation | Executable evidence |
| --- | --- | --- |
| Canonical signed objects | `internal/model` | digest, signature, expiry, mutation, and transition tests |
| Local configuration and adapter constraints | `internal/config` | strict JSON decoding and model validation |
| Private keys | `internal/keys` | exclusive creation, strict private-key modes, no-overwrite tests |
| Atomic durable state | `internal/statefile` | owner-only files, directory and symlink tests |
| Loopback boundary | `internal/netguard` | default loopback and non-loopback-refusal test |
| Requester catalog/request/receipt state | `internal/requester` | store lifecycle, bounded request-page, and read-only HTTP/UI tests |
| Harness-neutral typed MCP bridge | `internal/mcp`, `internal/requester/client.go` | offline initialization/tool registration, strict schemas, loopback transport, and conformance vectors |
| Trusted GitHub direct-exec adapter and review state | `internal/trusted/adapter.go`, `internal/trusted/store.go`, `internal/trusted/service.go` | exact argv/env, hostile argument, reservation-before-effect, ambiguous-outcome recovery, replay, retry, and receipt-binding tests |
| Trusted outbound polling | `internal/trusted/sync.go` | in-process v2/v1 receipt compatibility transport test and local smoke |
| Trusted web UI and local daemon control | `internal/trusted/server.go`, `internal/trusted/control.go` | web identity/CSRF, Unix-socket mode/stale-path, bounded control protocol, shared-executor, and spoof-resistance tests |
| CLI and process lifecycle | `cmd/airlock` | daemon-only control client, no fallback state/provider access, `go vet`, build through smoke, signal-aware shutdown |
| Deployment | `configs`, `deploy/systemd`, `docs/deployment.md` | example configs plus local smoke |

The provider boundary is one trusted direct child process. The adapter produces
an absolute configured `gh` executable plus exact validated argv; `os/exec`
receives it without shell parsing, PATH lookup, inherited environment, or
requester executable text. Requester/MCP/Hermes surfaces remain create/observe
only and never receive executor details.

The trusted daemon is the sole owner of `trusted-state.json`, its lock-free
in-memory action service, the signing key, receipt delivery, and the configured
`gh` process. The trusted web UI and the terminal CLI are separate frontends to
that same service. The CLI uses an owner-private Unix-domain socket and has no
direct state, signing, or provider capability.
