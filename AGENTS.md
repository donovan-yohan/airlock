# AGENTS.md

This repository is security-sensitive.

- Preserve the two-node boundary in `docs/adr/0001-two-node-authority-boundary.md`.
- Treat every request and catalog field as hostile data.
- Never execute requester-supplied shell text or deserialize into executable commands.
- Trusted adapters reconstruct commands from typed, locally validated fields.
- Do not add provider credentials, tokens, test secrets, or production identity material.
- Bind web services to loopback by default.
- Add negative tests for every authority or parser change.
- Run `go test ./...`, `go vet ./...`, and the repository's live smoke harness before handoff.
- Finish implementation with a simplify pass and rerun checks.
