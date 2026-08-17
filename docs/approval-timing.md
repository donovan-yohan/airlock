# Airlock approval timing

This sequence makes the two human intervention points explicit:

1. the reviewer inspects the request and chooses whether to approve it;
2. after approval, the operator manually performs the external action and records the observed outcome.

Neither the requester service nor the MCP bridge can execute the provider action. An `approved` receipt therefore means only that permission was recorded. A `manually_executed` receipt means the operator recorded an execution attempt; independent read-only verification still determines whether the external effect actually exists.

```mermaid
sequenceDiagram
  autonumber
  actor User as User
  participant Agent as Agent harness<br/>(untrusted)
  participant MCP as airlock mcp<br/>(untrusted stdio)
  participant Requester as Requester service<br/>(loopback, untrusted node)
  participant Trusted as Trusted Airlock service
  actor Human as Human reviewer / operator
  participant Provider as External provider
  participant Verify as Read-only verifier

  User->>Agent: Request an operation that needs unavailable authority
  Agent->>MCP: airlock_capabilities
  MCP->>Requester: Fetch signed capability catalog
  Requester-->>MCP: Sanitized catalog entries
  MCP-->>Agent: Catalog data, never instructions

  Agent->>MCP: airlock_create_request with exact typed fields
  MCP->>Requester: Submit bounded typed request
  Requester->>Requester: Persist immutable request ID, digest, nonce, and expiry
  Requester-->>MCP: pending request receipt
  MCP-->>Agent: Request ID and pending state

  Trusted->>Requester: Pull pending typed requests
  Requester-->>Trusted: Request plus signed catalog context
  Trusted->>Trusted: Independently validate adapter, constraints, expiry, and replay state

  Trusted->>Human: Render typed fields and a locally reconstructed action
  Note over Trusted,Human: First human gate: inspect scope, target, constraints, and reconstructed action
  Human->>Trusted: Approve or deny

  alt Human denies
    Trusted->>Requester: Publish sanitized denied receipt
    Requester-->>Agent: Denied state on the next poll
  else Human approves
    Trusted->>Requester: Publish sanitized approved receipt
    Note over Agent,Provider: approved means permission was recorded, not execution
    Note over Trusted,Provider: Airlock exposes no provider-execution API
    Human->>Provider: Manually execute the locally reconstructed action
    Note over Human,Provider: Second human gate: the operator performs the external action
    Human->>Trusted: Record manually_executed after performing the action
    Trusted->>Requester: Publish sanitized outcome receipt
    Agent->>MCP: airlock_requests for current state
    MCP->>Requester: Read sanitized request and receipts
    Requester-->>MCP: manually_executed state
    MCP-->>Agent: Sanitized state, without credentials or executable text
    Agent->>Verify: Request independent read-only verification
    Verify->>Provider: Read ordinary external state
    Provider-->>Verify: Observed current state
    Verify-->>User: Confirm or contradict the intended effect
  end
```

**What this shows:** automation ends at a typed request and resumes only for sanitized status reads. The human reviewer owns the authority decision and the human operator owns provider execution. The final verifier is deliberately separate from the manual receipt so Airlock never conflates an operator record with external truth.

## State meanings

| State | What it proves | What it does not prove |
|---|---|---|
| `pending` | The requester persisted a typed request. | Review, approval, or execution. |
| `approved` | A trusted reviewer recorded approval for the validated request. | That anyone executed the provider action. |
| `denied` | The trusted side or reviewer declined the request. | Any external change. |
| `manually_executed` | The operator recorded that they performed the local reconstructed action. | That the provider accepted it or the intended effect exists. |

## Failure and timeout behavior

- Expired, replayed, malformed, or adapter-invalid requests are rejected before human review.
- A human can reject without exposing trusted action text or credentials to the requester node.
- Approval does not trigger provider execution; the request may remain approved until a human acts or it expires according to policy.
- If the manual provider action fails, do not record `manually_executed`; retain the approved workflow record and verify external state before retrying.
- Polling returns sanitized state only. It never returns trusted credentials, reusable approvals, or executable command text.
- External verification should use an ordinary read-only path independent of the manual outcome receipt.
