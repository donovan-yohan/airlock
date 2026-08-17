# MVP implementation packet

Implement the accepted contract in `docs/adr/0001-two-node-authority-boundary.md`.

## Deliverable

A Go 1.25 module and one `airlock` binary with two services and a CLI:

- `airlock requester serve --config ...`
- `airlock trusted serve --config ...`
- `airlock trusted requests list --config ... [--cursor CURSOR]`
- `airlock trusted request {show,execute,deny} --config ... --id ...`
- `airlock request create ...`
- `airlock keygen ...`

Use the standard library unless a small dependency materially improves canonical JSON or security. Keep the dependency graph tiny and justified.

## Requester service

- Loopback bind by default; non-loopback requires an explicit unsafe flag.
- Durable local state with atomic writes and restrictive permissions.
- Accept and validate signed capability catalogs from the trusted node.
- Create typed requests only for catalog-advertised actions.
- Give each request a random ID and nonce, RFC3339 timestamps, expiry, and SHA-256 digest over deterministic canonical bytes.
- Request fields become immutable after creation.
- Accept trusted-node Ed25519 receipts only when signature, request digest, freshness, and state transition validate.
- Read-only human UI for catalog, pending requests, and receipts.
- No approve or execute endpoint.

## Trusted service

- Loopback bind by default; non-loopback requires an explicit unsafe flag.
- Pull pending requests from configured requester URL; requester never calls into trusted node.
- Validate requests against locally configured capabilities and versioned adapters, not requester catalog content.
- Trusted-rendered UI checks Tailscale identity headers against an explicit login allowlist and fails closed when absent outside `--dev`.
- Protect state-changing forms against CSRF and method confusion.
- The trusted daemon alone owns state, signing, receipt delivery, and `gh`. Its
  `0600` Unix socket in a `0700` trusted-state directory is a local-only control
  plane for the same Unix account; CLI callers cannot select a reviewer or send
  provider arguments, and never mutate state directly.
- Render exact request digest, action, arguments, expiry, reason, and locally derived command.
- Trusted execution: approve-and-execute persists a v2 approval/reservation before directly invoking configured absolute `gh` argv with a fixed environment; deny remains terminal. Do not invoke a shell, browser, arbitrary API, or requester-supplied command text.
- Sign receipts with the trusted Ed25519 key; never expose private key material.

## Initial adapter

`github.repo.add_collaborator`:

- owner and collaborator are fixed by the locally configured trusted capability;
- the capability ID identifies its configured GitHub owner;
- repository uses conservative GitHub name validation;
- permission is selected from the capability's local allowed set (`pull`, `push` for the example);
- locally derive a direct-exec `gh api --method PUT ...` argv plan;
- never accept a command or URL from requester.

## Config and sample deployment

- Separate example configs for requester and trusted node; no secrets.
- Tailscale Serve guidance and example ACL intent without modifying live Tailscale state.
- systemd user-unit templates for each role.
- local smoke script that starts both roles on ephemeral loopback ports, uses a fake absolute `gh` and isolated `GH_CONFIG_DIR`, executes one request through the trusted web UI and one through the trusted CLI, verifies v2 requester state and signed receipt pairs, and proves exactly two provider invocations.

## Tests

Include positive and negative tests for:

- canonical digest determinism;
- Ed25519 catalog and receipt verification;
- mutated request/display/receipt binding;
- unknown capability/action and invalid arguments;
- shell metacharacters/path traversal/oversized fields;
- expired request/catalog/receipt;
- replayed receipt and invalid state transitions;
- missing/spoofed Tailscale identity contract;
- CSRF and wrong HTTP methods;
- loopback binding defaults and non-loopback refusal;
- restrictive key/state permissions where the OS supports them;
- logs/UI/receipts not containing private keys or synthetic secret canaries.

## Verification gate

Run and record:

```bash
go test ./...
go test -race ./...
go vet ./...
./scripts/smoke-local.sh
```

Finish with a `/simplify`-style cleanup pass: remove avoidable abstractions and duplicate validation, rerun all gates, and leave the tree committed under the configured author identity.
