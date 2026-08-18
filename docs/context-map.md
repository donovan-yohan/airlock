# Command-broker context map

Airlock is one Go binary deployed in two roles. The requester owns no trusted credentials and can only propose or observe. The trusted daemon owns signing, durable decisions, local profile resolution, and execution of one exact human-approved plan.

| Concept | Implementation | Executable evidence |
| --- | --- | --- |
| Canonical v2 catalog/request and v3 receipt objects; legacy bytes | `internal/model` | determinism, mutation, signature, Unicode, size, and legacy-vector tests |
| Trusted-local profile configuration | `internal/config` | strict unknown-field, path, duration, label, URL, and compatibility-capability validation |
| Private keys and atomic state | `internal/keys`, `internal/statefile` | exclusive creation, restrictive modes, symlink refusal, atomic persistence tests |
| Requester catalog/request/receipt state | `internal/requester` | immutable proposals, current-client fail-closed behavior, legacy recovery, bounded pages |
| Typed model-facing bridge | `internal/mcp`, `internal/requester/client.go` | exact profile/argv schema, strict decoding, sanitized projections, conformance vectors |
| Plan resolution and pinned execution | `internal/trusted/adapter.go`, `internal/trusted/store.go`, `internal/trusted/source*.go`, `internal/trusted/process_linux.go` | plan-bound source identities, descriptor-pinned `gh`/`hosts.yml`, canonical root-owned Bubblewrap launcher revalidation, exact argv/env, trusted-only bounded output, timeout tests |
| Durable approval lifecycle | `internal/trusted/store.go`, `internal/trusted/service.go` | request/plan binding, reservation-before-effect, replay, simultaneous frontend, crash/persistence ambiguity tests |
| Trusted UI and local CLI control | `internal/trusted/server.go`, `internal/trusted/control.go`, `cmd/airlock` | canonical display, risk warnings, plan-digest confirmation, same-EUID socket, bounded responses |
| Outbound synchronization | `internal/trusted/sync.go` | current and historical signed receipt delivery/recovery tests |
| Deployment and public surfaces | `configs`, `deploy/systemd`, `docs`, `plugins`, `integrations/hermes` | smoke, bootstrap, docs/diagram, manifest/version, Hermes conformance tests |

The provider boundary is a Bubblewrap-contained direct child process. A current proposal supplies only `github.command/v1`, ordered argv, reason, timestamps, nonce, and ID. Trusted configuration supplies the static executable and SHA-256 identity, authority and policy labels, fixed environment, minimal `hosts.yml` source, bounded timeout, and trusted-only output-preview policy. Airlock stages descriptor-pinned private `gh` and `hosts.yml` copies, and revalidates the root-owned canonical launcher identity immediately before reservation; later path re-resolution is never execution input. Bubblewrap shares network, including host loopback, so it is not an egress firewall.

The daemon is the sole owner of `trusted-state.json`, invocation state, signing key, receipt delivery, and the child. Web and CLI are frontends to the same `ActionService`. The CLI uses an owner-private Unix socket and must echo the plan digest from a fresh `show`; neither frontend can edit a plan.

Requester state retains at most 192 records and trusted state at most 28; these caps include headroom for JSON's worst-case printable escaping and complete receipt/attempt histories. Trusted polling retrieves cursor-bounded pages rather than one all-or-nothing backlog. Same-UID trusted-control list pages expose at most one bounded record. Raw child output, credentials, trusted config paths, and resolved plans never cross to requester/MCP/Hermes.
