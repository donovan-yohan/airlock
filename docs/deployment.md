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
```

Start from `configs/requester.example.json` and
`configs/trusted.example.json`. Relative paths resolve from the config file's
directory. Create each state directory with mode `0700`; Airlock refuses a
group- or world-accessible state directory and writes state files with mode
`0600`.

The example systemd user units assume state under
`$HOME/.local/state/airlock/{requester,trusted}`. Copy the matching unit, then
use `systemctl --user enable --now ...`. Do not put credentials in a unit,
config, environment file, or catalog.

## State retention and rotation

Both node stores keep at most 4,096 request records so their worst-case state
remains below the atomic state-file ceiling. A full requester rejects new
requests, and a full trusted node rejects additional ingest; both continue
processing receipts and decisions for existing records. Expired records remain
only through the latest window in which a timely receipt could still be
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

## Manual decision semantics

`approved_for_manual_execution` means the reviewer has approved the exact
digest for manual use. It does not invoke or attest success at GitHub.
`manually_executed` is available only after approval and records the reviewer's
statement that they ran the displayed command. Although the ADR sketches an
optional evidence field, this MVP rejects every non-empty value: unrestricted
text cannot guarantee that a reviewer will not paste credential material.
Structured provider evidence is deferred. The requester should independently
verify provider state using its own separately authorized identity when
possible.

This two-step interpretation is the fail-closed resolution of the packet's
separate “approve” and “mark manually executed” actions. Denial is terminal.
