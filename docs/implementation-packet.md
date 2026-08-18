# Command-broker implementation packet

Implement the accepted contract in [`adr/0001-two-node-authority-boundary.md`](adr/0001-two-node-authority-boundary.md).

## Public commands

- `airlock requester serve --config ...`
- `airlock trusted serve --config ...`
- `airlock trusted requests list --config ... [--cursor CURSOR]`
- `airlock trusted request show --config ... --id ...`
- `airlock trusted request execute --config ... --id ... --plan-digest ...`
- `airlock trusted request deny --config ... --id ...`
- `airlock request create --config ... --profile github.command --profile-version v1 --arg ... --reason ...`
- `airlock mcp --requester-url ...`
- `airlock keygen ...`

## Requester contract

- Accept only a fresh signed `airlock.catalog/v2` profile when creating a current `airlock.request/v2` proposal.
- Canonically bind profile ID/version, ordered argv, reason, creation/expiry, nonce, and request ID.
- Reject mixed legacy/current fields, unknown profile/version, invalid UTF-8, NUL/control/ANSI/bidi, empty elements, and bounded-size violations.
- Preserve historical v1 add-collaborator requests plus v1/v2 receipts and durable state for recovery; do not reinterpret them as current commands.
- Expose create/observe only, with sanitized metadata and no output, trusted paths, credentials, or execution endpoint.

## Trusted contract

- Resolve `github.command/v1` only from trusted-local configuration. `shell.run/v1` is reserved and disabled.
- Persist the exact resolved plan and digest with the approval/running reservation before effect. Refuse stale shown plans, changed config, changed executable identity, mutation, replay, and simultaneous execution.
- Before reservation, stage descriptor-pinned private copies of the reviewed static `gh` and minimal `hosts.yml`; reverify the root-owned canonical Bubblewrap launcher path and digest immediately before reservation; execute only the pinned `gh` with exact reserved argv through that launcher, fixed environment, private work directory, bounded timeout, and trusted-only bounded sanitized stdout/stderr previews. Never invoke a shell or search PATH.
- Keep one active child independent of web/CLI disconnect, kill its process group on Linux timeout/cancellation, recover interrupted work as uncertain, and never retry implicitly.
- Render request/plan digests, every argv element, trusted-local labels, and broad-authority/risk warnings. Display is non-executable and non-editable.

## Verification

Run Go unit/race/vet, local fake-`gh` smoke, Python bootstrap/docs suites, Hermes locked pytest/ruff/compile/real-binary integration, cross-platform trusted builds, systemd verification, diagram generation/checks, and `git diff --check`. Prove one central generic-command regression test fails under a temporary legacy-only sabotage, restore it, run green, then finish with a simplify pass and repeat the gates.

All provider execution in tests must use fake `gh`; no test may mutate a real external provider or install live Airlock configuration.
