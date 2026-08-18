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

The trusted configuration must name absolute `github_cli_path` and
`sandbox_cli_path` (`/usr/bin/bwrap` in the example), an isolated
owner-private real `0700` canonical `github_config_dir`, a bounded
`execution_timeout`, a monotonic `profile_config_version`, bounded human-readable
authority/identity/sandbox/network/cwd/output labels, and `control_socket`. The
daemon binds regular non-symlink executable content and a root-owned UID 0,
non-writable canonical sandbox-launcher identity (including each path parent)
into every resolved-plan digest. The configured `sandbox_cli_path` is the
canonical launcher path the kernel executes; it is never copied into an
invocation directory. Airlock hashes and verifies that canonical path again
immediately before reservation. A root/admin replacement is therefore part of
the documented trusted-filesystem TCB, but an unexpected replacement fails the
approved path-and-digest binding closed. Do not inspect or log credential
contents.

Authenticate the canonical GitHub config before starting Airlock. The shipped
trusted systemd unit makes home read-only and permits writes only below the
trusted state directory, so it cannot create or authenticate this sibling
GitHub configuration directory for you. Pre-create and authenticate it as the
dedicated trusted account before enabling the unit:

```sh
install -d -m 0700 "$HOME/.local/state/airlock/gh-config"
GH_CONFIG_DIR="$HOME/.local/state/airlock/gh-config" /usr/local/bin/gh auth login
chmod 700 "$HOME/.local/state/airlock/gh-config"
chmod 600 "$HOME/.local/state/airlock/gh-config/hosts.yml"
```

Use the configured static `gh` path in place of `/usr/local/bin/gh` if you
installed it elsewhere. Airlock accepts only one private regular bounded
`hosts.yml`; aliases, extensions, and other persistent GitHub CLI configuration
are excluded. Its secret-safe content identity is reviewed, then an opened
no-follow descriptor is copied and hashed before durable reservation. The
static `gh` executable is likewise copied into the private invocation; bwrap is
not copied, so Ubuntu's path-keyed launcher policy remains applicable.

Bubblewrap creates fresh user, mount, PID, IPC, UTS, and cgroup namespaces and
dies with its parent. The host must permit unprivileged user namespaces. Verify
that requirement with the actual canonical launcher before deploying:

```sh
/usr/bin/bwrap --version
/usr/bin/bwrap --unshare-user --unshare-pid --die-with-parent \
  --ro-bind / / --proc /proc --dev /dev -- /bin/true
```

Use the configured `sandbox_cli_path` if it is not `/usr/bin/bwrap`. On Ubuntu
24.04 and later, AppArmor can restrict unprivileged user namespaces through a
path-keyed `bwrap-userns-restrict` policy. Keep `bwrap` installed at the
root-owned canonical path configured above; executing a user-owned copied
launcher can lose that path grant. Run this operator preflight before enabling
the service. Airlock verifies launcher identity at startup and again before
reservation, but it does not claim that those checks prove the host will permit
user namespaces. A later namespace denial can occur only after approval is
durably reserved and is recorded conservatively rather than launching an
unconfined provider command.

The supported `gh` is statically linked: the sandbox mounts the pinned
executable, invocation work directory, read-only minimal auth snapshot, and
only CA/DNS runtime files. It never mounts broad `/usr`, `/bin`, `/lib`, or
`/etc` trees. Signing state, all canonical config, control sockets, operator
home, and unrelated credentials are absent. GitHub network access shares the
host network; it is not an egress firewall and host loopback may be reachable
from the sandbox.

Install `gh` from the official [GitHub CLI release artifacts](https://cli.github.com/)
for the target architecture, verify the published release checksum, and place
the extracted binary at the configured path. Distribution packages are often
dynamically linked and are not automatically suitable. Check the exact file
before starting Airlock:

```sh
file "$(command -v gh)" # must report a static Linux ELF / statically linked executable
```

Airlock independently verifies that the configured `github_cli_path` is a
supported static Linux ELF before it can enter a plan. A dynamically linked
replacement is rejected rather than gaining broad library mounts or failing
after approval.

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
airlock trusted request execute --config "$HOME/.config/airlock/trusted.json" --id REQUEST_ID --plan-digest SHA256_FROM_SHOW --confirm-full-authority
airlock trusted request deny --config "$HOME/.config/airlock/trusted.json" --id REQUEST_ID
```

The local-control list response contains at most one sanitized record and an optional
`next_cursor`; pass it as `--cursor` to retrieve the next page.

The web reviewer must also tick the adjacent unchecked full-authority
confirmation after reading the exact plan. The control socket accepts only the
strict JSON pair `plan_digest` plus `confirm_full_authority: true`; a raw
same-UID control caller cannot substitute a digest-only request. These are
additional confirmations, not semantic safety guarantees.

Linux peer credentials are the local CLI authorization boundary. Airlock derives
the CLI reviewer identity from the daemon's Unix UID; the client cannot send a
reviewer name, header, token, credentials, or arbitrary command. Root is outside
this application threat model. The CLI must fail when the daemon or socket is
absent; it never falls back to direct state writes, signing, or `gh`.

The example systemd user units assume state under
`$HOME/.local/state/airlock/{requester,trusted}`. Copy the matching unit, then
use `systemctl --user enable --now ...`. Do not put credentials in a unit,
config, environment file, or catalog.

Both user-unit examples intentionally omit `PrivateDevices=` and
`CapabilityBoundingSet=`. An unprivileged user manager can fail before
`ExecStart` with `218/CAPABILITIES` while applying either directive. Bubblewrap
still creates the provider child's private `/dev`; both dedicated unprivileged
accounts retain `NoNewPrivileges=yes` and their role-specific namespace and
syscall restrictions. After installation, verify that both services actually
start and run one disposable fake-provider execution on the trusted node;
`systemd-analyze verify` checks syntax only.

## State retention and rotation

The requester keeps at most 192 requests. The trusted store keeps at most
28 requests and four bounded execution attempts per request. Those caps are
tested with quote/backslash-heavy values that maximize printable JSON escaping,
keeping complete request, receipt, attempt, and preview histories below the
shared atomic state-file ceiling. Trusted polling advances through bounded
cursor pages instead of requiring one whole backlog response. A full store
rejects new work but continues receipt delivery for existing records. Expired
records remain only through the latest window in which a timely receipt could
still be delivered, then are pruned.

Current TTL and capability limits govern new admissions, not historical signed
records. Restart uses stable protocol-envelope bounds to retain completed,
running, uncertain, and legacy history even after a TTL tightening or legacy
capability removal; a historical pending record that current policy no longer
allows remains preserved but is not actionable. A malformed, corrupt, or
signature-invalid state record—including after key rotation—fails startup with
the state bytes unchanged rather than deleting or rewriting audit history.

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

## Command profiles, trusted execution, and rollout

The signed catalog advertises `github.command/v1` with argv limits and the
trusted-local authority/sandbox/network/cwd/output labels. The requester may
propose any ordered argv supported by `gh`; adding an operation does not require
another Airlock adapter. It cannot select any trusted execution setting.
`shell.run/v1` is reserved but is not advertised and cannot execute until a
reviewed sandbox contract exists.

Before approval, web and CLI `show` render the profile/version, request and plan
digests, expiry/reason, every argv element distinctly, executable path and
content identity, fixed labels/policies, timeout/output policy, and suspicious
GitHub-shape warnings. The escaped command line is convenience text only. The
operator cannot edit it: deny and resubmit. The CLI `execute` must return the
exact plan digest from a fresh `show`; a config or executable change fails
closed.

`approved_for_execution` is durably signed and paired with the immutable
resolved plan and a local `running` attempt before the configured absolute `gh`
is started. The child receives a fixed minimal environment, including only its
fresh `GH_CONFIG_DIR`/`HOME`, noninteractive/no-color values, fixed locale, and
the reserved executable directory in `PATH`; ambient token, proxy, PATH, and
home configuration are not inherited. It is direct `os/exec`, never shell
parsing. Shell metacharacters are ordinary argv data.

Raw stdout and stderr never cross to receipts, requester state/API, MCP,
Hermes, ordinary logs, or agent-facing errors. The trusted review page alone
shows a small local-only preview after execution; it is UTF-8-normalized,
control/ANSI/invisible-character escaped, credential-redacted, and marked when
truncated or redacted. It is reviewer assistance only, not provider-state
proof. Child environment, provider bodies, credentials, and trusted config
paths likewise never cross to requester-facing state.

`executed` is emitted only after a zero exit and atomic completion persistence.
It does not prove GitHub state; independently read provider state. A missing
executable or other proven pre-invocation start failure is recorded as `failed`
and can be retried. A timeout, cancellation, interrupted daemon, generic
non-zero exit, expired completion, or completion-write failure is `uncertain`:
GitHub might already have accepted an operation. No ambiguous outcome
emits `executed`. A fresh explicit web or CLI retry is required after read-only
verification as appropriate. Airlock makes no operation-specific idempotence
claim.

After approval and the `running` reservation persist, a web or local-control
disconnect does not revoke daemon-owned execution. During daemon shutdown,
Airlock stops admitting executes, cancels active children, and waits within its
bounded shutdown deadline for their terminal persistence. A canceled child is
recorded as `uncertain` with `cancelled`; it never produces `executed`.

Upgrade requester integrations first, then the trusted node. Current creation
requires `airlock.catalog/v2` and fails closed against an old catalog. Current
execution emits `airlock.receipt/v3`, which binds the profile/version and plan
digest. Both nodes retain exact read/validation/recovery for historical
`airlock.request/v1`, manual `airlock.receipt/v1`, execution
`airlock.receipt/v2`, and prior durable state without reinterpreting their
bytes under command semantics.

## Command-broker upgrade and rollback boundary

Old PR #2 binaries use strict state/config decoding and cannot read current
command records in place. A binary-only downgrade is unsupported. Before
upgrading, stop both services and make one complete checkpoint of both
compatible configs and both state files; restore that exact checkpoint together
with the matching old binaries if rollback is required:

```sh
scripts/command-broker-rollback.sh snapshot \
  --confirm-services-stopped \
  --requester-config "$HOME/.config/airlock/requester.json" \
  --trusted-config "$HOME/.config/airlock/trusted.json" \
  --requester-state "$HOME/.local/state/airlock/requester/requester-state.json" \
  --trusted-state "$HOME/.local/state/airlock/trusted/trusted-state.json" \
  --directory "$HOME/.local/state/airlock/pre-command-broker-checkpoint"

# Stop current services, then restore every file before starting old binaries.
scripts/command-broker-rollback.sh restore \
  --confirm-services-stopped \
  --requester-config "$HOME/.config/airlock/requester.json" \
  --trusted-config "$HOME/.config/airlock/trusted.json" \
  --requester-state "$HOME/.local/state/airlock/requester/requester-state.json" \
  --trusted-state "$HOME/.local/state/airlock/trusted/trusted-state.json" \
  --directory "$HOME/.local/state/airlock/pre-command-broker-checkpoint"
```

`--confirm-services-stopped` is an operator interlock required for both actions;
it acknowledges that both services are stopped. It is not a claim that the
script can perfectly detect every running process. Every path argument must be
clean and absolute. The script walks every ancestor to the source, checkpoint,
and target mutation parent: no symlink, sticky, group-writable, or
world-writable component is accepted. Root-owned non-writable system ancestors
such as `/` and `/home`, and euid-owned read/search-only anchors such as a
conventional `0755` home directory, are accepted only because they cannot be
renamed by another user; every mutation parent and file remains euid-owned and
has no group/other permission bits. Restore also refuses duplicate target paths
or existing targets that alias the same inode. Its manifest must contain exactly
one lowercase SHA-256 line for each fixed checkpoint name, with no extra,
missing, or duplicate entry. Restore stages and validates all four files before
replacing any target, then uses private pre-restore backups to attempt
in-process recovery if a later replacement fails.

Each target replacement is an atomic rename within its own parent directory and
is synced, but the four targets can be in different directories. The complete
restore is therefore **not crash-atomic across directories**: power loss or a
kill between replacements can leave a mixed set. Keep services stopped, retain
the checkpoint, inspect a failed restore, and recover from the retained private
backups before restarting either service. It does not project command records:
those records are intentionally omitted from an old binary only by restoring the
pre-upgrade state snapshot. Current nodes read legacy v1 manual/v2 execution
receipts and legacy requests; a current requester with a legacy trusted catalog
fails closed for command creation, and an old trusted node cannot consume a
current command request. Restore compatible config and full state together,
never just the binary.

`github.command/v1` carries broad GitHub credential authority. Its risk labels
are reviewer assistance, not an allowlist. Approval is reviewer-approved RCE;
fresh config/cwd and Linux process-group cancellation reduce persistence and
cleanup risk but do not make the approved operation semantically safe or
prevent every abuse available to the credential and service identity.
