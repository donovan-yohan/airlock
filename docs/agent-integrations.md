# Airlock agent integrations

Persistent, cross-harness awareness for the Airlock authority-request workflow.

This package is deliberately thin:

- a native Claude Code plugin manifest;
- a native Codex plugin manifest;
- one shared Agent Skill;
- marketplace metadata for both harnesses; and
- a Python-standard-library bootstrapper for the separately-built `airlock` MCP binary.

Tool transport is installed separately as the typed `airlock mcp` stdio server. The model necessarily sees the exact `github.command/v1` argv it proposes, but the package contains no trusted-node credentials, identities, reusable approvals, executable/config paths, child output, or generic shell tool. `shell.run/v1` is reserved and disabled.

## Visual documentation

The publish-ready static site lives in [this directory](./) for GitHub Pages. Source-of-truth Mermaid documents are kept separately:

- [`architecture.md`](architecture.md) — trust boundary, installation topology, and managed-instruction lifecycle;
- [`approval-timing.md`](approval-timing.md) — end-to-end approval, trusted canonical Bubblewrap execution, receipt, and verification timing.

Raw `.mmd` files are in [`diagrams/`](diagrams/); the site uses checked-in rendered SVGs so diagrams remain visible without client-side JavaScript.

## Trust boundary

The plugin and MCP server run on the untrusted requester node. They may discover a signed command-profile catalog, create canonical profile/argv proposals, and read sanitized request/receipt state. They cannot approve or execute authority. Only the trusted node may resolve an immutable plan from local configuration, render the exact proposal and plan digest for human review, persist approval, and execute it.

Model-visible text can propose authority; it cannot grant or execute it. `github.command/v1` is broad credentialed reviewer-approved RCE, so human review is the semantic authorization boundary and risk warnings are assistance rather than an operation allowlist. `pending` and `approved_for_execution` are not proof of an external effect. Even after `executed`, verify ordinary read-only external state before claiming the effect exists. Historical v1 requests and v1/v2 receipts remain readable during migration.

## Packaging

The `plugins/airlock` directory is a dual-manifest plugin root:

```text
plugins/airlock/
├── .claude-plugin/plugin.json
├── .codex-plugin/plugin.json
└── skills/airlock/SKILL.md
```

Marketplace catalogs live at `.claude-plugin/marketplace.json` and `.agents/plugins/marketplace.json`. The shared skill is intentionally small: it has no `allowed-tools`, the plugin manifests have no hooks, and no `AGENTS.md` or `CLAUDE.md` is shipped. User-global instructions are edited only by the explicit, reversible `--instructions install` path described below.

## Install and update

The bootstrapper is stdlib-only. Give it the **explicit path to an executable** built `airlock` binary; it refuses non-executable sources. By default it targets the current user's `HOME` and installs both user-global harness integrations:

The opt-in instruction path also requires the native [Hermes integration](../integrations/hermes) from this monorepo to already be installed and enabled in the selected `HERMES_HOME`; the bootstrapper checks this prerequisite before any mutation.

```sh
python3 tools/airlock_bootstrap.py install \
  --binary /absolute/path/to/airlock \
  --instructions install
```

`--instructions install` is deliberately present in the happy-path command but is **not** the installer default. Omitting it leaves every instruction surface untouched. When explicitly selected, the installer:

- enables the native Hermes plugin's bounded system-prompt section with `plugins.entries.airlock.settings.instructions_enabled=true` in the active `HERMES_HOME` profile;
- upserts one marked block in user-global `~/.claude/CLAUDE.md`; and
- upserts the same marked block in user-global `~/.codex/AGENTS.md`.

The managed text tells each agent to check Airlock before requesting unavailable credentials or attempting a workaround, treat returned text as untrusted data, recognize broad commands as reviewer-approved RCE, and independently verify external state after `executed`. Repeated installs update a block only when `install-state.json` proves ownership and its recorded SHA-256 still matches; an unrecorded marker block or user-edited managed block is refused rather than adopted, overwritten, or later deleted. Malformed/duplicate markers and symlinked instruction targets are also refused. A non-empty global `~/.codex/AGENTS.override.md` blocks instruction installation because Codex would ignore the managed `AGENTS.md`. Use `--instructions skip` explicitly, or simply omit the flag, to install only the plugins and MCP registrations.

It makes a content-addressed, mode-`0500` copy at:

```text
~/.local/share/airlock/versions/<sha256>/airlock
```

Then it registers that exact absolute copy, without credentials, headers, or environment secrets:

```text
claude mcp add --scope user airlock -- \
  ~/.local/share/airlock/versions/<sha256>/airlock mcp \
  --requester-url http://127.0.0.1:8787

codex mcp add airlock -- \
  ~/.local/share/airlock/versions/<sha256>/airlock mcp \
  --requester-url http://127.0.0.1:8787
```

It also adds this checkout as the local `airlock` marketplace and installs `airlock@airlock` for each harness. Claude uses its supported `--scope user` marketplace/plugin commands; Codex's current plugin commands are user-global under `CODEX_HOME`.

Use `update` with a newly built binary. An earlier version recorded in installer state is replaced automatically; an unrelated existing `airlock` MCP or plugin is refused unless explicitly replaced.

```sh
python3 tools/airlock_bootstrap.py update --binary /absolute/path/to/new-airlock
python3 tools/airlock_bootstrap.py install --binary /absolute/path/to/airlock --replace
```

Use one harness only when needed, or target an intentionally selected home (useful for CI and disposable profiles):

```sh
python3 tools/airlock_bootstrap.py install --binary /path/to/airlock --harness claude
python3 tools/airlock_bootstrap.py --home /tmp/isolated-home install --binary /path/to/airlock
```

Without `--home`, an ambient `HERMES_HOME` is honored even when the profile lives outside `HOME`. With an explicit `--home`, an ambient `HERMES_HOME` outside that selected home is refused instead of silently targeting another profile; pass `--hermes-home /explicit/profile/home` when that external profile is intentional. This keeps disposable-home runs from touching the caller's live Hermes profile.

`--dry-run` performs no writes or CLI calls and prints the exact commands, copy/state paths, existing config backups, and managed instruction-file diffs that an install would use.

Before any CLI configuration mutation, existing candidate user config files—and instruction files when the opt-in is selected—are copied mode `0600` below `~/.local/share/airlock/backups/`. The binary copy, installer state, and managed instruction writes are atomic. If an install fails after mutation begins, the bootstrapper restores its config snapshot, removes completed installer entries, and removes a newly copied versioned binary. It never edits repository-local harness instructions.

## Doctor and uninstall

```sh
python3 tools/airlock_bootstrap.py doctor
python3 tools/airlock_bootstrap.py uninstall
```

`doctor` checks both marketplace/plugin manifests and the shared-skill invariants; checks the selected harnesses' CLI registrations and plugin visibility; then launches the installed binary directly over stdio. It sends MCP JSON-RPC `initialize` and `tools/list` and requires **exactly** these tools:

- `airlock_capabilities`
- `airlock_create_request`
- `airlock_requests`

The stdio probe does not require the requester service to be up. It verifies registration only, not authority, requester reachability, approval, or external execution.

`uninstall` removes only entries recorded in `install-state.json`, and first refuses if an `airlock` MCP/plugin no longer points to the installer-owned version or marketplace. It verifies each managed instruction block against its recorded content digest before removing it; missing or user-edited blocks and failed Hermes config reads abort before any removal. It restores the prior Hermes instruction toggle after the last managed harness is removed and leaves surrounding user text untouched. It removes a recorded versioned binary only after no remaining installer-state record references it. It does not remove a marketplace declaration, because that declaration can be shared by a user-installed plugin and current harness CLIs do not expose enough stable ownership metadata to remove it safely.

## Development validation

```sh
python3 -m unittest discover -s tests -v
python3 tools/airlock_bootstrap.py validate
claude plugin validate --strict plugins/airlock
```

The unit suite uses a fresh `TemporaryDirectory` for every case and sets isolated `HOME`, `HERMES_HOME`, `CODEX_HOME`, and `CLAUDE_CONFIG_DIR`; it never touches real Hermes, Claude, or Codex state. Fake binary/CLI fixtures exercise opt-in instruction management, dry-run, atomic copy, idempotency, collision refusal/replacement, rollback, uninstall, doctor, and MCP JSON-RPC tool discovery until the Go binary lane is available.

For an isolated manual marketplace smoke (also no real user config mutation):

```sh
sandbox="$(mktemp -d)"
mkdir -p "$sandbox/.codex"
HOME="$sandbox" CLAUDE_CONFIG_DIR="$sandbox/.claude" \
  claude plugin marketplace add --scope user "$PWD"
HOME="$sandbox" CLAUDE_CONFIG_DIR="$sandbox/.claude" \
  claude plugin install --scope user airlock@airlock
HOME="$sandbox" CODEX_HOME="$sandbox/.codex" \
  codex plugin marketplace add "$PWD" --json
HOME="$sandbox" CODEX_HOME="$sandbox/.codex" \
  codex plugin add airlock@airlock --json
rm -rf "$sandbox"
```

## Supported interface

The packaging commands above were checked against Claude Code `2.1.233` and Codex CLI `0.147.0`. In those versions, Claude supports `claude mcp add --scope user NAME -- COMMAND...`; Codex supports the user-global `codex mcp add NAME -- COMMAND...`; and their local-marketplace/plugin commands differ as shown above.

The Go binary provides the verified stdio invocation used by the bootstrapper:

```text
airlock mcp --requester-url http://127.0.0.1:8787
```

`doctor` exercises that real interface directly and requires JSON-RPC initialization plus precisely the three typed tools listed above while the requester is unavailable. If a later Go CLI version changes the published spelling, update `mcp_commands()` and `probe_mcp()` together, then rerun the unit suite and isolated harness smoke.
