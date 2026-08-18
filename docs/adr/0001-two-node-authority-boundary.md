# ADR 0001: two-node authority boundary

Status: accepted; exact-plan command brokering added

## Context

An autonomous host sometimes needs authority that it must not possess. Credential masking for authority an agent is allowed to use and Airlock approval for authority it is not allowed to use are different controls. Combining them creates a confused-deputy path: knowing that an authority exists must never attach that authority to the requester.

Airlock is a two-node, credential-isolated approval broker, not a per-operation permission DSL. An untrusted requester proposes exact executable content but cannot run it. A separate trusted node resolves a local execution profile, shows the proposal and resolved plan to a human, and executes only that exact immutable plan after explicit approval. The primary guarantee is **no unapproved execution**. Airlock does not claim that an approved arbitrary command is semantically safe.

## Decision

Build one Go binary with requester and trusted-node modes.

### Untrusted requester node

- Runs beside autonomous agent harnesses and stores no trusted provider credentials.
- Receives a signed `airlock.catalog/v2` catalog containing human-readable command-profile metadata and bounds. Existing typed capabilities remain signed compatibility data.
- Creates immutable `airlock.request/v2` proposals binding request ID, `github.command/v1`, ordered argv, reason, creation/expiry timestamps, nonce, and a SHA-256 digest over deterministic canonical bytes.
- Cannot select executable paths, credentials, environment, Unix identity, host cwd, timeout/resource settings, sandbox/network policy, reviewer, trusted endpoint, or control socket.
- Offers create/observe requester HTTP and MCP surfaces only. It cannot approve, execute, or mark a request successful.

### Trusted node

- Runs separately, initiates all cross-node polling, and keeps its signing key, canonical GitHub credential source, configuration, and execution authority local.
- Resolves `github.command/v1` to a clean absolute executable, its SHA-256 identity, fixed minimal environment, isolated credential/config copy, authority/identity/sandbox/network/cwd/output labels, bounded timeout, and local profile-config version.
- Shows every argv element distinctly with request and resolved-plan digests. Display text is never execution input and cannot be edited; the reviewer must deny and resubmit.
- Persists a signed `airlock.receipt/v3` approval and a `running` attempt containing the immutable resolved plan before child invocation. The plan digest binds the request digest, profile/version, executable path and content identity, exact argv, fixed labels/policy/config version, environment template, timeout, and all other non-secret execution settings. It never binds or persists credential material.
- Before durable reservation, stages the exact reviewed inputs from already-open descriptors: a private pinned static `gh` copy and the sole permitted private `hosts.yml` snapshot. It reopens the root-owned canonical Bubblewrap launcher, verifies its path-keyed identity against the resolved plan immediately before reservation, and invokes that canonical launcher with the reserved argv. It never invokes a shell or performs PATH lookup.
- Executes outside the store mutex while preserving one active invocation. Web and local CLI share one `ActionService`; frontend disconnect does not cancel the child. Replays and simultaneous web/CLI requests cannot start a second child.
- Uses an owner-private same-EUID Unix control socket. Trusted state, signing, execution, delivery, and ordered shutdown remain daemon-only.

### Human identity and transport

- Services bind to loopback by default and may be published with Tailscale Serve.
- Tailnet headers and an explicit trusted-login allowlist authenticate the reviewer. Tailnet is transport and authentication plumbing, not semantic authorization and not a reason to trust request content.
- Requester-to-trusted initiation is forbidden; Tailnet ACLs should reinforce the application boundary.

## Current command profile

`github.command/v1` is the first broad enabled profile. It accepts exact ordered `gh` argv, so any GitHub operation available through `gh` can be proposed without adding an Airlock adapter. Shell metacharacters such as `;`, `|`, `$()`, and redirections are ordinary argv bytes and are never interpreted by a shell.

The proposal contract bounds argv at 64 elements, each at 4096 bytes, with 32768 aggregate bytes and 65536 display bytes. IDs, reason, labels, argv, and other human-visible text must be valid UTF-8, non-empty where required, and free of NUL, C0/C1 controls, ANSI escapes, and bidirectional Unicode controls. Ambiguous mixed legacy/current fields and unknown fields fail closed.

A broad credentialed `gh` command is reviewer-approved RCE. Risk classification flags obvious auth/config/alias/extension changes, write API methods, merges, releases, workflow dispatch, visibility/transfer/archive/delete shapes, but is reviewer assistance—not an operation allowlist or semantic authorization engine.

`shell.run/v1` is a defined reserved profile identifier only. It is not advertised, cannot be proposed or executed, and stays disabled until an explicit sandbox contract is implemented and reviewed. Generic shell execution must not be hidden in the GitHub profile.

## GitHub isolation and output

Each invocation gets a new private working directory and an exact pinned copy of the sole canonical GitHub authentication file, `hosts.yml`; aliases, extensions, and other persistent GitHub configuration are excluded. The child sees a fixed environment containing only the reserved execution values; ambient `HOME`, `PATH`, `GH_*`/`GITHUB_*` token variables, proxy variables, requester text, and unrelated host state are not inherited. Symlinks, special files, oversized configuration, source replacement, and changed content identities fail closed. Invocation state is removed after completion and conservatively cleaned during crash recovery.

On Linux, Bubblewrap creates a filesystem/process boundary with fresh user, mount, PID, IPC, UTS, and cgroup namespaces, and dies with its parent. It mounts only the private invocation work directory, pinned static `gh`, read-only `hosts.yml` snapshot, and minimal CA/DNS runtime data. The network is deliberately shared so `gh` can reach GitHub: this is not an egress firewall and does not prevent host-loopback access. It does not make an approved broad command semantically safe or prevent every abuse available to the approved credential or service account.

Stdout and stderr are captured separately to small bounds, sanitized to safe UTF-8 display text, credential-redacted, and marked when truncated. The bounded preview persists only in trusted-local attempt state and appears only on trusted review surfaces. It never enters receipts, requester state/API, MCP, Hermes, ordinary logs, or agent-facing errors.

## Canonical objects and compatibility

Current objects use `airlock.catalog/v2`, `airlock.request/v2`, and `airlock.receipt/v3`. Current catalogs advertise profiles with authority/sandbox/network/cwd/output labels and bounded limits. Current receipts bind profile/version and the resolved-plan digest.

Readers preserve exact historical canonical bytes and recovery for:

- `airlock.request/v1` typed `github.repo.add_collaborator` requests;
- `airlock.receipt/v1` manual approval/execution receipts;
- `airlock.receipt/v2` trusted-execution receipts and existing durable attempts/state.

Historical requests are readable but are not silently reinterpreted under command semantics. A current client requires a current v2 catalog/profile and fails closed against an old catalog. Current execution emits only v3 receipts.

`approved_for_execution` proves that a human reserved one exact persisted plan. `executed` is emitted only when the direct child exits zero and terminal persistence succeeds. It does not prove provider state: neither that GitHub accepted the operation nor that its external effect still exists. An independent read-only verifier remains required. Timeout, cancellation, nonzero exit, interrupted recovery, and post-invocation persistence failure never emit `executed`; ambiguous cases become `uncertain` and have no implicit retry.

## Non-negotiable invariants

- Model-visible content may propose authority but cannot grant or execute it.
- No trusted credential crosses to requester, catalog, receipt, MCP, log, or public documentation.
- The executed plan exactly matches the request and plan digests approved by the reviewer.
- Approval/reservation persistence precedes effect; failure prevents invocation.
- Unknown, expired, replayed, malformed, mutated, stale-config, stale-executable, or unsupported objects fail closed.
- Requester text reaches no shell interpreter, though approved `github.command/v1` argv is executable data for `gh`.
- A compromised requester may spam or lie, but cannot execute without exact-plan human approval on the trusted surface.

## OpenShell and other sandbox boundaries

Airlock does not replace isolation for authority an agent is allowed to use. Any autonomous execution graph—including delegated CLIs, browsers, MCP servers, shell workers, and remote workers—must remain behind its own verified sandbox or scoped broker. Owner credentials must never be attached to that graph merely because Airlock knows they exist. An ordinary host-side coding CLI is not a credential broker.

## Rejected alternatives

- **Approval UI served by requester:** a compromised requester can lie about the executable plan.
- **Owner credential on requester with confirmation:** confirmation does not restore the missing credential boundary.
- **Editable trusted plan:** review no longer binds the submitted immutable request.
- **Shell hidden behind `github.command/v1`:** violates the profile contract and changes the reviewed interpreter authority.
- **Output redaction as isolation:** attacker-controlled output can evade redaction and release private data.
- **Per-operation GitHub adapters:** cannot provide the deliberately broad profile without code changes for every operation.

## Deferred

- An explicit sandbox contract and implementation for `shell.run/v1`.
- Network egress or host-loopback restrictions beyond the Bubblewrap filesystem/process sandbox.
- Mobile-native approver, passkey step-up, and stronger OS/network sandboxing.
