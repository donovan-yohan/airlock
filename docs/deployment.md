# Deployment guidance

## Prepare each node

Build the same binary on each machine with Go 1.25:

```sh
go build -trimpath -o "$HOME/.local/bin/airlock" ./cmd/airlock
```

On the trusted node only, generate the signing keypair. Keep the private path
on that node and copy only the `.pub` file to the requester node:

```sh
airlock keygen \
  --private "$HOME/.config/airlock/trusted.key" \
  --public "$HOME/.config/airlock/trusted.pub"
```

On each node, install the matching example as
`$HOME/.config/airlock/{requester,trusted}.json`. Put the trusted private key at
`$HOME/.config/airlock/trusted.key`; put the copied public key at
`$HOME/.config/airlock/trusted.pub` on the requester. The shipped relative paths
then resolve to the exact locations allowed by the systemd units. Prepare them
before starting either service:

```sh
install -d -m 0700 "$HOME/.config/airlock"
install -d -m 0700 "$HOME/.local/state/airlock/requester"
install -d -m 0700 "$HOME/.local/state/airlock/trusted"
install -d -m 0700 "$HOME/.local/state/airlock/gh-config"
```

Start from `configs/requester.example.json` and
`configs/trusted.example.json`. Relative paths resolve from the config file's
directory. Create each state directory with mode `0700`; Airlock refuses a
group- or world-accessible state directory and writes state files with mode
`0600`.

The trusted configuration must name an absolute `github_cli_path`, an isolated
owner-private real `0700` `github_config_dir`, a bounded `execution_timeout`,
and `control_socket`. The daemon creates a missing GitHub config directory with
mode `0700` and refuses a symlink, non-directory, or group- or world-accessible
directory. Do not inspect or log its credential contents.

Relative directory and socket paths resolve from the trusted config file. The
socket must be a direct child of the trusted state directory. The daemon creates it
with mode `0600` inside an owner-private `0700` directory, rejects a symlink or
non-socket at that path, removes only a safely detected stale socket, and
removes its socket during clean shutdown. It is never served over the Tailnet
or the TCP web listener. A sibling owner-only `0600` lifecycle-lock file is
held for the daemon lifetime, so a second daemon cannot clean up, replace, or
bind the active socket; the kernel releases that lock if the daemon crashes.

The local control plane requires Linux. Before HTTP can receive bytes, the
daemon reads each accepted Unix-socket peer's `SO_PEERCRED` and requires its UID
to equal the daemon's effective UID. Directory and socket modes remain
defense-in-depth only; they are not treated as equivalent authentication. On an
unsupported platform, the trusted daemon refuses to start its control socket
rather than falling back to filesystem-mode authorization.

Authenticate the configured CLI in its isolated directory before starting the
trusted service; authentication is an operator setup step and never occurs in
the web UI. Do not use a home-wide GitHub CLI config directory.

Run the trusted user service and terminal controls as the same dedicated,
unprivileged Unix account. Same-UID Linux peer credentials are the local control
authorization boundary, not an individual human identity: any process running
under the trusted daemon UID can authorize CLI actions. Deploy a dedicated
trusted/operator Unix account with no untrusted agent processes, and do not
share that account with unrelated services:

```sh
airlock trusted requests list --config "$HOME/.config/airlock/trusted.json" [--cursor CURSOR]
airlock trusted request show --config "$HOME/.config/airlock/trusted.json" --id REQUEST_ID
airlock trusted request execute --config "$HOME/.config/airlock/trusted.json" --id REQUEST_ID
airlock trusted request deny --config "$HOME/.config/airlock/trusted.json" --id REQUEST_ID
```

The local-control list response contains at most four sanitized records and an optional
`next_cursor`; pass it as `--cursor` to retrieve the next page.

Linux peer credentials are the local CLI authorization boundary. Airlock derives
the CLI reviewer identity from the daemon's Unix UID; the client cannot send a
reviewer name, header, token, credentials, or arbitrary command. Root is outside
this application threat model. The CLI must fail when the daemon or socket is
absent; it never falls back to direct state writes, signing, or `gh`.

The example systemd user units assume state under
`$HOME/.local/state/airlock/{requester,trusted}`. Copy the matching unit, then
use `systemctl --user enable --now ...`. Do not put credentials in a unit,
config, environment file, or catalog.

## State retention and rotation

The requester keeps at most 4,096 requests. The trusted store keeps at most
1,024 requests and four bounded execution attempts per request, keeping its
worst-case JSON below the shared atomic state-file ceiling. A full store rejects
new work but continues receipt delivery for existing records. Expired records
remain only through the latest window in which a timely receipt could still be
delivered, then are pruned.

On restart, records that no longer validate under tightened TTL bounds or the
configured trusted public key are removed instead of crash-looping the service.
Rotating the trusted key also removes the old signed catalog and any records
whose receipts were signed by the prior key. Back up the state file first when
its audit history must be retained outside Airlock. Malformed JSON and unsafe
state-file permissions still fail startup rather than being silently repaired.

## Tailscale Serve and ACL intent

Keep both Airlock listeners on explicit loopback IPs. Publish each loopback
listener through Tailscale Serve on its own node; for current Tailscale CLI
versions the shape is:

```sh
tailscale serve --bg http://127.0.0.1:8787
```

Run the equivalent command with port `8788` on the trusted node. Confirm the
installed Tailscale version's Serve syntax and HTTPS URL before enabling the
units. Do not pass `--unsafe-non-loopback` for a normal Tailnet deployment.

The tailnet policy should express these relationships (illustrative intent,
not a copy-paste policy):

- intended human reviewers may reach both Serve HTTPS surfaces;
- the trusted-node identity may reach the requester Serve surface;
- the requester-node identity has no grant to initiate traffic to the trusted
  node;
- unrelated tailnet identities have no grant to either surface.

Tailscale Serve must be the only path to the production trusted UI because it
injects `Tailscale-User-Login`. Airlock requires that header to exactly match
`allowed_logins`. Direct exposure of the loopback backend through another
proxy would break the identity-header trust contract. `--dev` disables the
Tailscale header and instead requires `X-Airlock-Dev-Identity`; use it only for
local smoke/testing.

## Trusted execution semantics and rollout

`approved_for_execution` is durably signed and paired with a local `running`
attempt before the configured absolute `gh` is started. The child receives a
fixed minimal environment, including only the isolated `GH_CONFIG_DIR`,
noninteractive/no-color settings, safe HOME/locale, and fixed PATH; inherited
tokens, proxies, and home configuration are not supplied. It is direct
`os/exec`, never shell parsing.

`executed` is emitted only after a zero exit and atomic completion persistence.
It does not prove GitHub state; independently read provider state. A missing
executable or other proven pre-invocation start failure is recorded as `failed`
and can be retried. A timeout, cancellation, interrupted daemon, generic
non-zero exit, expired completion, or completion-write failure is `uncertain`:
GitHub might already have accepted the collaborator PUT. No ambiguous outcome
emits `executed`. A fresh explicit web or CLI retry is required after read-only
verification as appropriate. The GitHub endpoint documents `201` for a new
invitation and `204` for existing access; Airlock does not treat that as a
formal duplicate-invitation retry guarantee.

After approval and the `running` reservation persist, a web or local-control
disconnect does not revoke daemon-owned execution. During daemon shutdown,
Airlock stops admitting executes, cancels active children, and waits within its
bounded shutdown deadline for their terminal persistence. A canceled child is
recorded as `uncertain` with `cancelled`; it never produces `executed`.

Upgrade requester integrations first, then the trusted node. Older requester
versions reject `airlock.receipt/v2` and its new decisions. Both upgraded nodes
retain read/validation/recovery for v1 `approved_for_manual_execution` and
`manually_executed` history. Receipts and attempts intentionally omit output,
environment, provider body, credentials, and free-form command text.
