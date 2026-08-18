# Airlock approval and trusted-execution timing

The reviewer performs one deliberate action: **Approve and execute**. Airlock
stages the exact reviewed private `gh` and `hosts.yml` snapshots from
already-open descriptors, revalidates the root-owned canonical Bubblewrap
launcher immediately before reservation, then persists a signed
`approved_for_execution` receipt, the exact resolved plan, and a bounded local
`running` attempt. It invokes only the pinned `gh` copy with the reserved
requester-proposed argv through that launcher. No shell parses it.

Requester/MCP/Hermes surfaces can create and observe requests only. They never
receive an execution endpoint, reusable approval, credential, trusted path, or
child output. `executed` means the trusted child process returned success and completion persisted; it does not prove provider state, so ordinary read-only verification still determines it.

```mermaid
sequenceDiagram
  autonumber
  actor User as User
  participant Agent as Agent harness<br/>(untrusted)
  participant MCP as airlock mcp<br/>(untrusted stdio)
  participant Requester as Requester service<br/>(loopback, untrusted node)
  participant Trusted as Trusted Airlock service
  actor Human as Trusted reviewer
  participant Provider as GitHub CLI / provider
  participant Verify as Read-only verifier

  Agent->>MCP: Propose github.command/v1 ordered argv
  MCP->>Requester: Persist immutable ID, request digest, expiry
  Trusted->>Requester: Pull pending hostile proposal
  Trusted->>Trusted: Resolve trusted profile and plan digest
  Trusted->>Human: Show digests, distinct argv, local policy, risks
  Human->>Trusted: Approve exact plan digest or deny
  alt reviewer denies
    Trusted->>Requester: Publish denied receipt
  else reviewer approves
    Trusted->>Trusted: Stage opened gh and hosts.yml snapshots and reverify canonical bwrap identity
    Trusted->>Trusted: Atomically persist approved_for_execution + immutable plan + running attempt
    Trusted->>Provider: Bubblewrap runs pinned gh with fixed environment
    Note over Trusted,Provider: Shared network with bounded sanitized previews kept trusted-only
    alt child exits zero and completion persists
      Trusted->>Trusted: Atomically persist executed receipt + succeeded attempt
      Trusted->>Requester: Publish approved_for_execution then executed receipts
      Requester-->>MCP: executed state
    else pre-invocation failure or ambiguous child outcome
      Trusted->>Trusted: Persist bounded failed or uncertain attempt
      Note over Trusted,Human: No executed receipt. Verify externally before any explicit retry.
    end
  end
  Agent->>Verify: Independently read provider state
  Verify-->>User: Confirm or contradict intended effect
```

## State and receipt meanings

| State/receipt | What it proves | What it does not prove |
|---|---|---|
| `pending` | The requester persisted an exact profile/argv proposal and digest. | Review, approval, or execution. |
| `approved_for_execution` | A reviewer authorized one persisted resolved-plan digest. | Provider invocation or effect. |
| `running` / `failed` / `uncertain` | Trusted-local bounded attempt status. | Provider success or failure details. |
| `executed` | The trusted direct child returned success and completion receipt persisted. | GitHub accepted or retains the intended effect. |
| v1 `approved` / `manually_executed`, v2 execution receipt | Historical recoverable evidence. | Current v3 plan-binding semantics or provider truth. |

## Failure and retry behavior

- Persistence is before effect; a failed approval/reservation write does not
  invoke `gh`.
- The store mutex is released before child execution. Concurrent or replayed
  POSTs find `running` and cannot create another provider call.
- Stdout/stderr are separately bounded, UTF-8-sanitized, credential-redacted,
  and marked when truncated for trusted review only. No preview, environment,
  provider body, credential, or trusted path is released through
  requester/MCP/Hermes, receipts, or ordinary logs. Attempt failures use a
  small enumerated code only.
- A restart changes `running` to `uncertain` with an `interrupted` attempt code;
  it never resumes a child. A missing executable or failed process start is the
  only `failed` outcome. Executable identity drift also fails before invocation.
  Timeout, cancellation, generic non-zero exit, and an interrupted child are
  `uncertain` because GitHub may already have accepted an operation.
  Reviewers may explicitly retry `failed` or `uncertain` attempts after the
  required external verification. Airlock makes no operation-specific retry
  idempotence claim.
- If a child may have succeeded but terminal persistence failed, Airlock records
  uncertainty (or restart recovery does) and never emits `executed`. Verify
  provider state before an explicit retry.
- Bubblewrap confines the child to its invocation filesystem/process namespace:
  pinned `gh`, private work, read-only `hosts.yml`, and minimal CA/DNS data.
  Network remains shared, including host loopback, so this is not an egress
  firewall. The approved broad credentialed command remains reviewer-approved
  RCE.
