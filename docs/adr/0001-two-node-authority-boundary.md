# ADR 0001: two-node authority boundary

Status: accepted for MVP

## Context

An autonomous development host should be able to discover that a human-owned authority exists and request a bounded action without receiving that authority's credential. Separately, credentials explicitly granted to the agent should not be readable by the model or its tools.

Those are different controls:

1. **OpenShell/NemoClaw credential brokering** protects credentials the agent is allowed to use. The sandbox sees endpoint-bound placeholders, while the egress proxy injects real values after network and credential-binding policy checks.
2. **Airlock authority requests** cover credentials the agent is not allowed to use at all. The agent may know an authority and capability descriptor exists, but only a separate trusted node can render or execute a request.

Combining them would recreate a confused-deputy path. An owner credential must never be attached to an agent sandbox merely because Airlock knows it exists.

## Decision

Build one Go binary with requester and trusted-node modes.

### Untrusted requester node

- Runs beside autonomous Hermes on the development box.
- Stores no external-service credentials other than the agent's own separately brokered identity.
- Receives a signed capability catalog containing metadata only: authority ID, action IDs, argument schemas, constraints, expiry, and trusted-node public key.
- Creates immutable typed requests with an ID, capability, action, arguments, reason, creation time, expiry, nonce, and canonical payload digest.
- Offers a read-only Tailnet UI and API for request status.
- Cannot approve, execute, or mark a request successful.

### Trusted node

- Runs on a separate always-on device where autonomous development does not occur.
- Initiates outbound polling to the requester. The requester cannot initiate a connection to the trusted node; Tailnet ACLs should enforce this in addition to application design.
- Keeps its private signing key and any human credentials local.
- Validates every request against locally installed, versioned adapter code and constraints. Requester-supplied shell text is not a valid action.
- Renders the request in a UI served by the trusted node itself. The requester must not provide the approving UI code.
- Derives commands and URLs locally from typed arguments.
- MVP is manual-only: copy/open actions are allowed, automatic execution is absent.
- Signs receipts over the exact request digest and human decision. Receipts contain no credential material.

### Human identity

- Both services bind to loopback by default and are published only through Tailscale Serve.
- Tailnet ACLs restrict the requester UI to intended users and prevent requester-node initiation toward the trusted node.
- The trusted UI checks Tailscale identity headers and an explicit login allowlist. Missing identity fails closed outside an explicit development mode.
- Tailscale identity authenticates the reviewer but does not make requester content trustworthy.

## Canonical objects

### Capability catalog entry

```json
{
  "id": "github:example-owner",
  "display_name": "Example GitHub authority",
  "actions": ["github.repo.add_collaborator"],
  "constraints": {
    "owner": "example-owner",
    "collaborator": "example-agent",
    "permissions": ["pull", "push"]
  },
  "expires_at": "RFC3339 timestamp"
}
```

The catalog says what may be requested. It grants nothing. The trusted adapter and local human decision remain authoritative.

### Request

```json
{
  "version": "airlock.request/v1",
  "id": "req_<random>",
  "capability_id": "github:example-owner",
  "action": "github.repo.add_collaborator",
  "arguments": {
    "repository": "example",
    "permission": "push"
  },
  "reason": "Invite the automation account to the repository",
  "created_at": "RFC3339 timestamp",
  "expires_at": "RFC3339 timestamp",
  "nonce": "random value",
  "digest": "sha256 of canonical payload without digest"
}
```

### Receipt

A trusted-node Ed25519 signature covers the request digest, decision, reviewer identity, trusted adapter version, timestamp, and optional externally observable evidence. A receipt is an attestation, not proof of external state; the requester independently verifies provider state whenever its own identity can observe it.

## MVP adapter

`github.repo.add_collaborator` accepts only:

- owner and collaborator fixed by the local trusted capability catalog;
- repository matching GitHub's conservative repository-name grammar;
- permission in the locally allowed set.

It derives this command locally:

```bash
gh api --method PUT \
  repos/OWNER/REPOSITORY/collaborators/COLLABORATOR \
  -f permission=PERMISSION \
  --silent
```

No arbitrary command action exists.

## Non-negotiable invariants

- Model-readable content may request authority but cannot grant it.
- No human or provider credential crosses from trusted node to requester.
- No requester-provided string reaches a shell interpreter as executable code.
- Display and receipt bind to the same canonical request digest.
- Unknown, expired, replayed, malformed, mutated, or unsupported requests fail closed.
- Trusted-node private keys and credentials never appear in logs, receipts, catalogs, requests, or UI responses.
- A compromised requester may spam or lie in requests, but cannot cause execution without a human decision on trusted-rendered content.

## OpenShell/NemoClaw boundary

The full autonomous execution graph—not merely the top-level Hermes process—must move behind NVIDIA's official NemoClaw/OpenShell boundary or an equivalent scoped broker. OpenShell providers place opaque placeholders in a sandbox and resolve them only at endpoint-bound HTTP egress. That protection is bypassed if Hermes delegates to host-side Codex, Claude, OpenHands, browser processes, MCP servers, shell workers, or remote nodes that can independently read host credentials or send unrestricted egress.

Child harnesses therefore have only three acceptable placements:

1. run inside an OpenShell sandbox with their own provider bindings and policy;
2. run as an outside broker that accepts typed requests, owns no broader authority than intended, and never returns credentials or an unrestricted execution channel;
3. run on another node with an equivalent independently verified sandbox/broker boundary.

An ordinary host-side coding CLI is not a broker. If it receives a repository checkout, host home, OAuth files, or unrestricted network access, it remains an untrusted harness outside the claimed boundary. NemoClaw carries Hermes-specific runtime guards and a host-side broker for Nous OAuth/tool credentials, but each additional harness and tool transport still needs explicit placement and tests.

Migration requirements:

- attach only agent-owned or explicitly agent-owned provider identities;
- never attach owner credentials;
- inventory every process Hermes can spawn or call, including delegated coding CLIs, subprocess tools, MCP servers, browser automation, messaging bridges, and remote workers;
- deny host execution fallbacks: a sandboxed Hermes must not silently delegate protected work to an unsandboxed host harness;
- use HTTPS/API flows that OpenShell can inspect and bind; raw SSH and opaque tunnels do not receive credential rewriting;
- keep sandbox filesystem mounts explicit and exclude the host home, SSH directory, GitHub CLI config, Hermes plaintext `.env`, and OAuth files;
- migrate skills, memories, sessions, and cron state through a credential-filtered snapshot;
- choose a supported brokered inference route. Current ChatGPT Codex OAuth file auth is not treated as safely brokered until an explicit host-side route is proven;
- test denied exfiltration, wrong-host placeholder use, disallowed GitHub methods/repos, raw environment reads, config display, unrestricted egress, and restart persistence before switching the live gateway.
- exercise every delegated harness path and prove from inside each process that raw credentials, host auth stores, and unrestricted egress are unavailable.

## Rejected alternatives

- **Approval UI served only by requester:** compromised requester can lie about what will execute.
- **Store an owner PAT on requester with a confirmation button:** confirmation does not restore the missing credential boundary.
- **Send generated shell commands directly to an executor:** typed display does not matter if execution consumes different attacker-controlled text.
- **Use output redaction without process/filesystem/network isolation:** the model can still read or exfiltrate the secret before output filtering.
- **Attach an owner as an OpenShell provider:** masks the bytes but still grants autonomous use of the authority, defeating Airlock.

## Deferred

- Automatic execution of allowlisted adapters.
- Mobile-native approver app and custom URL scheme.
- Passkey step-up for high-risk actions.
- Organization/team-wide GitHub administration.
- General-purpose shell or sudo requests.
