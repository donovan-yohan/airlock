# Airlock

Airlock is a two-node, credential-isolated approval broker. It lets an untrusted AI agent propose exact executable content without receiving credentials or any path to execute it. A separate trusted node resolves local execution policy, shows the exact proposal and resolved plan to a human, and executes only that immutable plan after explicit approval.

It uses a two-node design:

- the **requester node** exposes a signed profile catalog, accepts canonical command proposals, and returns sanitized request and receipt state;
- the **trusted node** holds the signing key, credentials, and local profile configuration, resolves a concrete plan, persists its digest with the approval reservation, and directly executes the exact approved argv.

The first enabled profile is `github.command/v1`. It passes requester-proposed argv directly to a configured absolute `gh` executable without a shell. It intentionally supports arbitrary GitHub operations available through `gh`; a new operation does not require a new Airlock adapter. This is broad, credentialed, reviewer-approved RCE—not a semantic safety policy. `shell.run/v1` is reserved but disabled and non-executable until an explicit sandbox contract is implemented and reviewed.

A request is not authorization. `approved_for_execution` records one exact resolved-plan reservation; `executed` only attests that the trusted child process returned success and completion persisted. It does not prove provider state; independent read-only provider verification is still required before an agent claims the effect happened. Historical v1 manual receipts, v2 execution receipts, and v1 add-collaborator requests remain readable without being reinterpreted as the current command protocol.

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

Airlock is intentionally strict about who may execute and intentionally broad about what a human may approve:

- requester and MCP input is always hostile data;
- requester-proposed `gh` argv is executable only after a human approves its exact immutable resolved plan;
- the requester cannot choose executable paths, credentials, environment, identity, cwd, network/sandbox policy, timeout, reviewer, trusted endpoint, or control socket;
- the trusted profile supplies a descriptor-pinned absolute executable and minimal `hosts.yml` snapshot, their SHA-256 identities, a fixed minimal environment, Bubblewrap confinement, fresh cwd, bounded timeout, and displayable authority/policy labels; no shell or PATH lookup is used;
- argv and display validation reject invalid UTF-8, NUL, controls, ANSI, bidirectional Unicode, ambiguous empty fields, and oversized proposals; shell metacharacters remain ordinary argv data;
- every invocation receives fresh private `hosts.yml` and work snapshots, ambient token/proxy/HOME variables are not inherited, Bubblewrap mounts only the invocation surface, and raw stdout/stderr never leave the trusted review boundary;
- capability catalogs and receipts are signed with Ed25519;
- requester-facing services bind to loopback by default;
- no provider credentials, tokens, or production identities belong in this repository;
- instructions are opt-in and cannot grant authority.

Fresh GitHub state and Bubblewrap limit persistent alias/extension/config poisoning and host filesystem/process exposure. Network remains shared so `gh` can reach GitHub (including host loopback): this is not an egress firewall, and Airlock does not prevent abuse available to an approved credential.

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
airlock trusted request execute --config "$HOME/.config/airlock/trusted.json" --id REQUEST_ID --plan-digest SHA256_FROM_SHOW --confirm-full-authority
airlock trusted request deny --config "$HOME/.config/airlock/trusted.json" --id REQUEST_ID
```

The CLI never reads trusted state, loads the signing key, or invokes `gh`; it
requires the running trusted daemon and reports the daemon's persisted state.
`show` distinctly renders every argv element, the request and plan digests,
trusted-local labels, and risk warnings. There is no trusted-side edit path:
deny and resubmit instead. List returns at most one sanitized record and an optional `next_cursor`; pass
that value with `--cursor` to read the next page. `execute` also requires the
deliberately explicit `--confirm-full-authority` acknowledgement; a digest is
not an authority bypass.

The requester CLI creates the same canonical proposal accepted by MCP:

```sh
airlock request create --config requester.json \
  --profile github.command --profile-version v1 \
  --arg api --arg repos/example/project --arg --method --arg GET \
  --reason "Inspect repository metadata"
```

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
