# Airlock architecture diagrams

These diagrams describe Airlock's two-node, credential-isolated approval boundary. The cross-harness package remains on the untrusted requester node: it proposes exact `github.command/v1` argv and observes sanitized state, but holds no credentials, approval, or execution authority.

The dedicated approval timeline is in [`approval-timing.md`](approval-timing.md). Raw Mermaid sources live in [`diagrams/`](diagrams/) and are kept byte-for-byte aligned with the fenced diagrams below.

## Trust boundary and runtime topology

```mermaid
flowchart TB
  subgraph U["Untrusted requester node"]
    direction LR
    User["User"]
    Harness["Hermes / Claude Code / Codex"]
    Awareness["Native plugin or shared skill<br/>awareness only"]
    MCP["airlock mcp<br/>typed stdio server"]
    Requester["Requester service<br/>127.0.0.1:8787"]
    RequestState[("Immutable requester state<br/>exact proposals + sanitized receipts")]
  end

  subgraph T["Trusted node"]
    direction LR
    Trusted["Trusted Airlock service"]
    Profile["Trusted local github.command/v1 profile<br/>executable identity + fixed policy"]
    Review["Human review UI<br/>exact proposal + resolved plan"]
    TrustedState[("Signed approval + immutable plan<br/>one active attempt")]
  end

  Human["Human reviewer / operator"]
  Provider["External provider"]
  Verify["Independent read-only verifier"]

  User -->|"asks for an authority-requiring operation"| Harness
  Awareness -->|"adds bounded usage guidance"| Harness
  Harness -->|"calls exactly three typed tools"| MCP
  MCP -->|"sends loopback HTTP JSON"| Requester
  Requester -->|"persists profile, ordered argv, digest, expiry"| RequestState
  Trusted -->|"pulls pending requests"| Requester
  Requester -->|"returns hostile proposal and signed catalog data"| Trusted
  Trusted -->|"resolves only trusted execution settings"| Profile
  Profile -->|"produces digest-bound immutable plan"| Review
  Human -->|"approves or denies exact resolved plan"| Review
  Review -->|"persists approval and plan before effect"| TrustedState
  TrustedState -->|"pinned gh + hosts.yml; Bubblewrap; trusted-only preview"| Provider
  Trusted -->|"publishes sanitized signed receipt"| Requester
  Harness -->|"polls sanitized request state"| MCP
  Verify -->|"reads ordinary external state"| Provider
  Verify -->|"reports observed effect"| User
```

**What this shows:** requester argv is executable content, but it cannot execute on the requester. Trusted-local configuration resolves all authority-bearing settings, and a human approves one exact request/plan digest before Airlock stages the matching opened executable and `hosts.yml` snapshots, revalidates the root-owned canonical Bubblewrap launcher, persists the reservation, and invokes the pinned `gh` copy through that launcher. Bubblewrap confines filesystem/process access but deliberately shares network (including host loopback): this is not an egress firewall. Trusted-only bounded sanitized previews do not make a broad credentialed command semantically safe. An `executed` receipt does not prove provider state; it is followed by independent read-only verification.

## Installation and ownership topology

```mermaid
flowchart TD
  Source["Explicit executable<br/>airlock binary"]
  Repo["This plugin checkout<br/>dual manifests + shared skill"]
  Bootstrap["airlock_bootstrap.py"]
  Validate["Preflight validation<br/>loopback URL, collisions, ownership"]
  Versioned["Content-addressed binary<br/>~/.local/share/airlock/versions/&lt;sha256&gt;/airlock"]
  Mode{"--instructions mode"}
  Registrations["MCP + marketplace/plugin registrations"]
  State[("install-state.json<br/>owned paths, selectors, digests")]
  Backups[("Mode-0600 persistent<br/>config backups")]

  subgraph C["Claude Code user scope"]
    ClaudeMCP["airlock stdio MCP registration"]
    ClaudePlugin["airlock@airlock plugin"]
    ClaudeRules["~/.claude/CLAUDE.md<br/>digest-owned marker block"]
  end

  subgraph X["Codex user scope"]
    CodexMCP["airlock stdio MCP registration"]
    CodexPlugin["airlock@airlock plugin"]
    CodexRules["~/.codex/AGENTS.md<br/>digest-owned marker block"]
  end

  subgraph H["Selected Hermes profile"]
    HermesPlugin["Native hermes-plugin-airlock<br/>installed and enabled prerequisite"]
    HermesToggle["instructions_enabled = true<br/>bounded prompt section"]
  end

  Source -->|"supplies explicit executable input"| Bootstrap
  Repo -->|"supplies marketplace and plugin metadata"| Bootstrap
  Bootstrap -->|"runs before any mutation"| Validate
  Validate -->|"copies mode 0500 by content hash"| Versioned
  Validate -->|"selects explicit or default behavior"| Mode
  Mode -->|"skip — default"| Registrations
  Mode -->|"install — explicit opt-in"| HermesPlugin
  HermesPlugin -->|"proves prompt extension can activate"| HermesToggle
  Mode -->|"installs managed Claude guidance"| ClaudeRules
  Mode -->|"installs managed Codex guidance"| CodexRules
  Versioned -->|"pins exact executable path"| ClaudeMCP
  Versioned -->|"pins exact executable path"| CodexMCP
  Registrations -->|"configures user MCP"| ClaudeMCP
  Registrations -->|"configures user MCP"| CodexMCP
  Repo -->|"installs expected selector"| ClaudePlugin
  Repo -->|"installs expected selector"| CodexPlugin
  Bootstrap -->|"records only installer-owned state"| State
  Bootstrap -->|"snapshots candidate config before writes"| Backups
```

**What this shows:** the bootstrapper never discovers or builds an arbitrary executable. It copies one explicit binary by hash, pins both MCP registrations to that immutable path, treats awareness instructions as a separate opt-in, and records enough ownership state to refuse unsafe updates or removals.

## Managed instruction lifecycle

```mermaid
flowchart LR
  Clean["No Airlock markers<br/>no instruction ownership record"]
  Managed["Canonical managed block<br/>path + SHA-256 recorded"]
  Updated["Canonical block refreshed<br/>new digest recorded"]
  Removed["Owned block removed<br/>surrounding bytes preserved"]
  Unowned["Airlock markers exist<br/>without ownership state"]
  Tampered["Managed block missing<br/>or digest mismatch"]
  Refused["Fail closed<br/>no instruction mutation"]
  HermesOn["Hermes prompt section enabled<br/>prior boolean recorded"]
  HermesRestored["Prior Hermes boolean restored<br/>after last managed harness"]

  Clean -->|"explicit install with clear target"| Managed
  Managed -->|"reinstall or update with matching digest"| Updated
  Updated -->|"becomes current managed state"| Managed
  Managed -->|"uninstall with matching digest"| Removed
  Managed -->|"user edits or deletes owned block"| Tampered
  Unowned -->|"install refuses adoption"| Refused
  Tampered -->|"install, update, doctor, or uninstall detects drift"| Refused
  Managed -->|"shares instruction lifecycle"| HermesOn
  HermesOn -->|"last managed harness is uninstalled"| HermesRestored
```

**What this shows:** marker comments alone are not ownership. The installer also records the target path and content digest. A matching record permits idempotent refresh or precise removal; missing state, changed content, failed Hermes reads, and malformed targets fail before mutation.

## Non-goals visible in the diagrams

- No enabled generic shell runner. `shell.run/v1` remains disabled until a reviewed sandbox contract exists.
- Requester-proposed `github.command/v1` argv becomes executable only as the exact human-approved resolved plan; no shell parses it.
- No trusted credentials, approval tokens, or provider execution URLs cross to the requester node.
- No hook automatically converts another tool failure into an Airlock request.
- Risk warnings assist review but do not create an operation allowlist. Approved broad credentialed commands are reviewer-approved RCE.
- `approved_for_execution` is not provider execution, and `executed` is not independent proof of the external effect. Historical v1 requests and v1/v2 receipts remain readable.
- The cross-harness package does not install the native Hermes plugin; it verifies that prerequisite before enabling its prompt section.
