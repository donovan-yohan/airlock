# Airlock for Hermes

Native Hermes tools for requesting authority through [Airlock](../..) without giving the agent privileged credentials.

The plugin is deliberately thin. It talks only to the Airlock **requester** service on a loopback IP literal, follows no redirects, accepts no credentials, and never connects to the trusted node. Airlock independently validates the current signed profile catalog, canonical command proposal, receipts, expiry, replay, and state transitions.

## Tools

- `airlock_capabilities` — discover the signed capabilities accepted by the requester.
- `airlock_create_request` — propose exact ordered `github.command/v1` argv for human review. It never executes the proposal.
- `airlock_requests` — recover recent requests or read one request's trusted receipt state.

When the plugin is enabled, Hermes registers these model-facing tools and the bundled `airlock` skill. The skill's short description is part of Hermes's skill index, while its full procedure and deferred tool schemas load only when relevant. That remains the default persistence mechanism: no global prompt mutation or per-repository `AGENTS.md` edit is required. An optional bounded plugin-owned system-prompt section can be explicitly enabled as described below.

For the complete operating procedure and state semantics, load the bundled skill explicitly with `skill_view("airlock:airlock")`. The skill makes the capability discoverable; tool schemas define the typed interface. Neither is an authorization source.

## Install

Validate from this checkout:

```bash
hermes plugins doctor . --ci
```

For local development, copy or symlink this directory to the active profile's
`plugins/airlock` directory, then enable it and start a new Hermes session:

```bash
hermes plugins enable airlock
```

Hermes's community plugin index supports monorepo subdirectories. Once Airlock
is listed there, install the pinned entry with `hermes plugins install airlock
--enable`. Until then, use a reviewed checkout rather than an unpinned branch.

Configure only non-secret local settings:

```yaml
plugins:
  enabled:
    - airlock
  entries:
    airlock:
      settings:
        requester_url: http://127.0.0.1:8787
        timeout_seconds: 5.0
        instructions_enabled: false
```

Set `instructions_enabled: true` only as an explicit awareness opt-in. The plugin then registers a section through Hermes's supported `register_system_prompt_section` API; it does not replace the system prompt, add hooks, or edit global/project instruction files. The cross-harness bootstrapper checks that this native plugin is installed and enabled before setting the option.

The URL must be plain HTTP on an explicit loopback IP and port. `localhost`, remote hosts, paths, query strings, fragments, embedded credentials, and redirects are refused.

## Semantics

`github.command/v1` is broad: it can propose arbitrary operations supported by `gh`, and a new operation does not require another adapter. Its argv elements are model-visible request data, including shell metacharacters that remain literal because the trusted node never invokes a shell. It is credentialed reviewer-approved RCE, not a semantic safety policy. `shell.run/v1` is reserved but disabled and non-executable.

`airlock_create_request` returning `pending` means only that the local requester accepted and persisted a proposal. `approved_for_execution` means a trusted reviewer authorized one exact resolved-plan digest. `executed` only records that the trusted child returned success and completion persisted. External state still needs verification before claiming the requested effect exists; historical v1 requests and v1/v2 receipts remain readable for recovery.

Hermes receives proposed profile/argv and sanitized receipt metadata. It never receives the resolved executable/config path, credentials, environment, child output, or provider response. Unknown extra fields are rejected or omitted from the model-facing projection.

This is not a Hermes approval transport. Hermes tool approvals govern Hermes-owned tool execution; Airlock requests authority held on another node and cannot auto-approve or auto-execute it.

## Development

```bash
uv run --locked pytest
uv run --locked ruff check hermes_plugin_airlock tests
uv run --locked python -m compileall -q __init__.py hermes_plugin_airlock tests
hermes plugins doctor . --ci
```

To exercise the real Go requester and trusted catalog sync instead of the fake transport, build Airlock and pass the binary to the integration test:

```bash
go -C ../.. build -o /tmp/airlock ./cmd/airlock
AIRLOCK_BINARY=/tmp/airlock uv run --locked pytest -q tests/test_real_airlock.py
```

Default tests use fake loopback transports and synthetic data; the opt-in integration test generates an ephemeral keypair and deletes it with its temporary directory. Never add real keys, tokens, production identities, or trusted-node access to this repository.
