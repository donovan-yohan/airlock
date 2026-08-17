# Spike: OpenShell-managed Codex OAuth for Hermes

## tl;dr

**Build, do not fork—but treat this as an execution-graph migration, not a Hermes wrapper.** OpenShell already supports imported provider profiles, OAuth 2 refresh-token grants, refresh-token rotation, multiple header credentials, endpoint binding, and credential-driver storage. The missing work is an upstream-friendly Hermes/NemoClaw integration:

1. a Codex provider profile and host-side login bootstrap;
2. a Hermes external-credential mode that consumes OpenShell placeholders instead of reading or refreshing `auth.json`;
3. an explicit `ChatGPT-Account-ID` placeholder because Hermes cannot derive that claim from an opaque access-token placeholder.

This protects only processes inside the policy boundary. Every delegated harness that can touch protected data or egress—Codex CLI, Claude Code, OpenHands, browser workers, MCP servers, shell subprocesses, and remote execution nodes—must either run inside OpenShell, sit behind a typed least-privilege broker, or have an equivalent independently verified boundary. Leaving a credential-capable host-side harness beside sandboxed Hermes defeats the architecture.

Fork OpenShell only if the OAuth exchange later requires semantics that its generic refresh strategy cannot express and NVIDIA declines a reusable extension. Maintaining a security-runtime fork should be the last option.

Sources pinned at:

- `NVIDIA/OpenShell@c4b500a7de64d0b66e3ee8098f58d14299092162`
- `NVIDIA/NemoClaw@fee824811e28cc74899873fd3ce84f305e79e411`
- `NousResearch/hermes-agent@9b1a2a14ca4a1e76d85591579c7d8fcaa0656782`

## Can OpenShell support custom OAuth without a fork?

Yes, when the provider uses a conventional OAuth 2 refresh-token or client-credentials grant.

OpenShell provider profiles support a `refresh` object with a token URL, scopes, refresh timing, secret/non-secret material, and additional outputs.[^openshell-profile] Its gateway-mintable strategies include `oauth2_refresh_token` and `oauth2_client_credentials`.[^openshell-strategies] The refresh-token implementation sends a form-encoded grant with `client_id`, `refresh_token`, optional `client_secret`, and optional scopes.[^openshell-refresh] It accepts a newly rotated `refresh_token`, persists it in refresh state, and atomically replaces the provider credential.[^openshell-rotation]

OpenShell also supports several credentials in one provider profile, each with its own environment placeholder, auth style, and header name.[^openshell-headers] That covers Codex's bearer token plus its account header.

## Does Codex fit that generic flow?

Mostly.

Hermes already refreshes Codex with a standard form-encoded OAuth request:

- token URL `https://auth.openai.com/oauth/token`;
- grant type `refresh_token`;
- public client ID;
- refresh token;
- optional rotated refresh token in the response.[^hermes-refresh]

That maps directly to OpenShell's built-in refresh strategy.

The special case is `ChatGPT-Account-ID`. Hermes currently decodes the real access-token JWT to extract `chatgpt_account_id` for Codex requests and catalog probes.[^hermes-account] In an OpenShell deployment Hermes receives an opaque placeholder, not the JWT, so decoding must stop. A host-side login bootstrap should extract the stable account ID once and store it as a second OpenShell provider credential. Hermes then sends a second placeholder header and OpenShell substitutes its value at egress.

## Proposed provider profile

Illustrative shape; exact field names and paths must be linted against the pinned OpenShell release:

```yaml
id: openai-codex-hermes
category: agent
credentials:
  - name: access_token
    env_vars: [OPENAI_CODEX_ACCESS_TOKEN]
    required: true
    auth_style: bearer
    header_name: Authorization
    refresh:
      strategy: oauth2_refresh_token
      token_url: https://auth.openai.com/oauth/token
      refresh_before_seconds: 300
      max_lifetime_seconds: 3600
      material:
        - { name: client_id, required: true, secret: false }
        - { name: refresh_token, required: true, secret: true }
  - name: account_id
    env_vars: [OPENAI_CODEX_ACCOUNT_ID]
    required: true
    auth_style: header
    header_name: ChatGPT-Account-ID
endpoints:
  - host: chatgpt.com
    port: 443
    protocol: rest
    enforcement: enforce
    rules:
      - allow: { method: POST, path: "/backend-api/codex/responses" }
      - allow: { method: GET, path: "/backend-api/codex/models**" }
      - allow: { method: GET, path: "/backend-api/wham/usage" }
binaries:
  - /usr/local/bin/hermes
  - /opt/hermes/.venv/bin/python
```

Do not grant a broad `chatgpt.com/**` rule. Add only live-observed paths required by Hermes, then pin them in tests.

## Required Hermes/NemoClaw changes

### Execution-graph coverage

- inventory every direct and delegated execution path reachable from Hermes;
- classify each path as in-sandbox, typed broker, separately sandboxed remote node, or prohibited;
- remove host fallback paths that can read host homes, OAuth stores, GitHub CLI state, SSH agents, browser profiles, Docker sockets, or unrestricted network interfaces;
- run negative credential and egress tests from every supported child harness, not only from the parent Hermes process;
- treat a new harness/plugin/MCP as a security-boundary change requiring policy and regression evidence.

### Hermes

Add an explicit managed Codex credential mode:

- enabled only when both managed placeholder environment variables are present;
- does not load, import, refresh, or write Codex tokens in `auth.json` or `~/.codex/auth.json`;
- returns the access-token placeholder as the runtime API key;
- sends the account-ID placeholder in every Codex request, model-catalog request, quota probe, and auxiliary request;
- fails closed if one placeholder is missing;
- identifies the source as externally managed in diagnostics without printing values.

This should be a reusable environment-backed mode, not NemoClaw-specific branching scattered through request code.

### NemoClaw

- ship/import the provider profile;
- add a host-side device-login/bootstrap command;
- keep the refresh token and account ID in the configured OpenShell credential backend;
- attach the provider and managed Hermes environment during sandbox creation;
- exclude Codex and Hermes auth stores from imported state;
- pin OpenShell and sandbox image digests.

### OpenShell

No core change is required for the first proof. If a reusable onboarding callback is desirable, propose it upstream rather than forking.

## Acceptance tests

1. Host bootstrap completes device/browser OAuth without placing tokens in the sandbox.
2. Sandbox process environment contains placeholders, never access or refresh tokens.
3. `auth.json`, `.codex/auth.json`, host home, and GitHub CLI config are absent from sandbox mounts.
4. An actual Hermes GPT-5.6 turn succeeds through `chatgpt.com/backend-api/codex`.
5. The expected `ChatGPT-Account-ID` header is injected without Hermes decoding the JWT.
6. Forced expiry rotates access and refresh tokens; the next turn succeeds after gateway and sandbox restart.
7. Wrong-host, wrong-path, and disallowed-method attempts fail before credentials are injected.
8. Config display, logs, traces, process listings, crash output, snapshots, and receipts contain no raw credential material.
9. Removing the provider or breaking the profile fails closed; Hermes does not fall back to a host auth file or direct unbrokered endpoint.
10. OpenShell/NemoClaw/Hermes exact versions and image digests are recorded in deployment evidence.
11. Every supported delegated harness is exercised and proven unable to read host credentials or bypass policy egress; unsupported host-side delegation fails closed.

## Risks and gaps

- OpenShell is early-preview software and NemoClaw pins exact compatible releases; upgrades need security regression tests.
- Codex's ChatGPT backend is not the public OpenAI API contract. Endpoint paths, headers, or OAuth behavior may change.
- The host bootstrap must safely handle account selection and refresh-token single-use behavior. Sharing one refresh token with Codex CLI or another Hermes instance would recreate rotation conflicts.
- The account ID is treated as stable for one provider instance. A login that changes accounts must atomically replace both the OAuth material and account ID.
- This spike did not execute a live Codex request through OpenShell. That proof is the next gated work package.

## Recommendation

Build this as a narrow proof after the Airlock MVP contract is stable. Keep it separate from Airlock: OpenShell manages the agent-authorized Codex identity; Airlock continues to protect identities the agent must never possess.

[^openshell-profile]: `crates/openshell-providers/src/profiles.rs` lines 142-184 — refresh profile schema and materials.
[^openshell-strategies]: `crates/openshell-providers/src/profiles.rs` lines 679-693 — gateway-mintable refresh strategies.
[^openshell-refresh]: `crates/openshell-server/src/provider_refresh.rs` lines 714-778 — OAuth refresh-token and client-credentials dispatch and forms.
[^openshell-rotation]: `crates/openshell-server/src/provider_refresh.rs` lines 398-475 — rotated refresh-token persistence and generation-safe credential replacement.
[^openshell-headers]: `crates/openshell-providers/src/profiles.rs` lines 94-105 and 1577-1630 — per-credential env vars, auth styles, and header names.
[^hermes-refresh]: `hermes_cli/auth.py` lines 3800-3931 — Codex refresh request, error handling, and rotation.
[^hermes-account]: `hermes_cli/auth.py` lines 4251-4265 and `hermes_cli/codex_models.py` lines 97-138 — account ID extraction and request header behavior.
