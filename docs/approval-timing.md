# Airlock approval and trusted-execution timing

The reviewer performs one deliberate action: **Approve and execute**. Airlock
first persists a signed `approved_for_execution` receipt and a bounded local
`running` attempt. Only then does the trusted node directly invoke its locally
reconstructed `gh` argv. This is not a shell or requester action.

Requester/MCP/Hermes surfaces can create and observe requests only. They never
receive an execution endpoint, reusable approval, credential, or executor
detail. `executed` means the trusted child process returned success; ordinary
read-only verification still determines provider state.

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

  Agent->>MCP: Create exact typed request
  MCP->>Requester: Persist immutable ID, digest, expiry
  Trusted->>Requester: Pull pending typed request
  Trusted->>Trusted: Revalidate local adapter and derive direct-exec plan
  Trusted->>Human: Show exact executable and argv
  Human->>Trusted: Approve and execute
  alt reviewer denies
    Trusted->>Requester: Publish denied receipt
  else reviewer approves
    Trusted->>Trusted: Atomically persist approved_for_execution + running attempt
    Trusted->>Provider: Direct exec configured absolute gh with fixed environment
    alt child exits zero and completion persists
      Trusted->>Trusted: Atomically persist executed receipt + succeeded attempt
      Trusted->>Requester: Publish approved_for_execution then executed receipts
      Requester-->>MCP: executed state
    else pre-invocation failure or ambiguous child outcome
      Trusted->>Trusted: Persist bounded failed or uncertain attempt
      Note over Trusted,Human: No executed receipt. Reviewer inspects before explicit retry.
    end
  end
  Agent->>Verify: Independently read provider state
  Verify-->>User: Confirm or contradict intended effect
```

## State and receipt meanings

| State/receipt | What it proves | What it does not prove |
|---|---|---|
| `pending` | The requester persisted a typed request. | Review, approval, or execution. |
| `approved_for_execution` | A reviewer authorized a persisted attempt. | Provider invocation or effect. |
| `running` / `failed` / `uncertain` | Trusted-local bounded attempt status. | Provider success or failure details. |
| `executed` | The trusted direct child returned success and completion receipt persisted. | GitHub accepted or retains the intended effect. |
| v1 `approved` / `manually_executed` | Historical manual workflow evidence. | New trusted-execution semantics or provider truth. |

## Failure and retry behavior

- Persistence is before effect; a failed approval/reservation write does not
  invoke `gh`.
- The store mutex is released before child execution. Concurrent or replayed
  POSTs find `running` and cannot create another provider call.
- No stdout, stderr, environment, provider body, credential, or free-form
  command is persisted or rendered. Attempt failures use a small enumerated
  code only.
- A restart changes `running` to `uncertain` with an `interrupted` attempt code;
  it never resumes a child. A missing executable or failed process start is the
  only `failed` outcome. Timeout, cancellation, generic non-zero exit, and an
  interrupted child are `uncertain` because GitHub may have accepted the PUT.
  Reviewers may explicitly retry `failed` or `uncertain` attempts after the
  required external verification. GitHub documents `201` for a new invitation
  and `204` for existing access, not a duplicate-invitation retry guarantee.
- If a child may have succeeded but terminal persistence failed, Airlock records
  uncertainty (or restart recovery does) and never emits `executed`. Verify
  provider state before an explicit retry.
