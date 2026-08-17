# Airlock

Airlock lets untrusted AI agents request narrow, human-reviewed authority without receiving credentials or direct execution access.

It uses a two-node design:

- the **requester node** exposes a signed capability catalog, accepts typed requests, and returns sanitized request and receipt state;
- the **trusted node** holds the signing key and local policy, reconstructs one allowlisted action from validated fields, and executes its configured absolute GitHub CLI directly after trusted human approval.

A request is not authorization. `approved_for_execution` records a trusted reservation; `executed` only attests that the trusted child process returned success. Independent read-only provider verification is still required before an agent claims the effect happened. Historical v1 `manually_executed` receipts remain readable.

## Repository layout

```text
cmd/airlock/                  Go CLI and services
internal/                     authority model, requester, trusted node, MCP server
configs/                      neutral example configuration
deploy/systemd/               hardened user-service examples
plugins/airlock/              shared Claude Code and Codex skill package
integrations/hermes/          native Hermes plugin
tools/airlock_bootstrap.py    cross-harness installer and doctor
tests/                        bootstrapper and documentation tests
docs/                         security docs and GitHub Pages site
```

## Security boundary

Airlock is intentionally narrow:

- requester and MCP input is always hostile data;
- requester-supplied shell text is never executed;
- trusted adapters reconstruct a direct-exec plan only from typed, locally configured, validated fields; no shell or PATH lookup is used;
- capability catalogs and receipts are signed with Ed25519;
- requester-facing services bind to loopback by default;
- no provider credentials, tokens, or production identities belong in this repository;
- instructions are opt-in and cannot grant authority.

Read the [two-node authority ADR](docs/adr/0001-two-node-authority-boundary.md) before changing protocol, policy, or adapter behavior.

## Build and run locally

Airlock requires Go 1.25.

```sh
go build -o ./dist/airlock ./cmd/airlock
./dist/airlock --help
```

Generate an ephemeral local keypair and adapt the example configs:

```sh
mkdir -p .airlock/keys
go run ./cmd/airlock keygen \
  --private .airlock/keys/trusted.key \
  --public .airlock/keys/trusted.pub
```

The deployment guide covers requester and trusted-node startup, state paths, and systemd hardening: [docs/deployment.md](docs/deployment.md).

With the trusted service running under its dedicated Unix account, its local
operator CLI talks only to the daemon-owned control socket:

```sh
airlock trusted requests list --config "$HOME/.config/airlock/trusted.json" [--cursor CURSOR]
airlock trusted request show --config "$HOME/.config/airlock/trusted.json" --id REQUEST_ID
airlock trusted request execute --config "$HOME/.config/airlock/trusted.json" --id REQUEST_ID
airlock trusted request deny --config "$HOME/.config/airlock/trusted.json" --id REQUEST_ID
```

The CLI never reads trusted state, loads the signing key, or invokes `gh`; it
requires the running trusted daemon and reports the daemon's persisted state.
List returns at most four sanitized records and an optional `next_cursor`; pass
that value with `--cursor` to read the next page.

## Agent integrations

The same repository ships three thin, requester-only integration surfaces:

- native Hermes tools in [`integrations/hermes`](integrations/hermes/README.md);
- a shared Claude Code and Codex skill package in [`plugins/airlock`](plugins/airlock);
- the typed stdio MCP server exposed by `airlock mcp`.

The bootstrapper installs a content-addressed binary copy, registers the MCP server, and installs the local Claude/Codex marketplace package. Global instruction changes happen only when `--instructions install` is explicitly supplied.

```sh
python3 tools/airlock_bootstrap.py install \
  --binary /absolute/path/to/airlock

python3 tools/airlock_bootstrap.py doctor
```

See [the agent integration guide](docs/agent-integrations.md) for dry-run, update, instruction opt-in, collision handling, and uninstall behavior.

## Verify

```sh
go test ./...
go test -race ./...
go vet ./...
./scripts/smoke-local.sh

python3 -m unittest discover -s tests -v
python3 tools/airlock_bootstrap.py validate

cd integrations/hermes
uv run --locked pytest -q
uv lock --check
uv run --locked ruff check hermes_plugin_airlock tests ../../tests
uv run --locked python -m compileall -q __init__.py hermes_plugin_airlock tests ../../tests
hermes plugins doctor . --ci
cd ../..
```

The real Hermes integration test can launch the Go requester and trusted catalog sync with an ephemeral keypair:

```sh
go build -o /tmp/airlock ./cmd/airlock
cd integrations/hermes
AIRLOCK_BINARY=/tmp/airlock uv run --locked pytest -q tests/test_real_airlock.py
```

## Documentation

The GitHub Pages site is built from [`docs/`](docs/). Source Mermaid diagrams live in [`docs/diagrams/`](docs/diagrams/) and checked-in SVGs keep the site usable without client-side JavaScript.

## License

MIT. See [LICENSE](LICENSE).
