package model

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestRequestDigestDeterministicAndMutationBound(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	first := validRequest(now)
	second := first
	second.Argv = append([]string(nil), first.Argv...)
	if err := SetRequestDigest(&first); err != nil {
		t.Fatal(err)
	}
	if err := SetRequestDigest(&second); err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("equivalent argv changed digest: %s != %s", first.Digest, second.Digest)
	}
	second.Reason = "mutated after display"
	if err := VerifyRequestDigest(second); err == nil {
		t.Fatal("mutated request retained a valid digest")
	}
}

func TestCatalogAndReceiptSignaturesBindPayload(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	catalog := validCatalog(now)
	if err := SignCatalog(&catalog, privateKey); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCatalogSignature(catalog, publicKey); err != nil {
		t.Fatal(err)
	}
	catalog.Capabilities[0].Constraints.Owner = "attacker"
	if err := VerifyCatalogSignature(catalog, publicKey); err == nil {
		t.Fatal("mutated catalog signature verified")
	}

	request := validRequest(now)
	if err := SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	receipt := validReceipt(now, request)
	if err := SignReceipt(&receipt, privateKey); err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceiptSignature(receipt, publicKey); err != nil {
		t.Fatal(err)
	}
	receipt.RequestDigest = strings.Repeat("0", 64)
	if err := VerifyReceiptSignature(receipt, publicKey); err == nil {
		t.Fatal("mutated receipt binding verified")
	}
}

func TestHostileGitHubArgumentsFailClosed(t *testing.T) {
	tests := []map[string]string{
		{"repository": "repo;echo-owned", "permission": "push"},
		{"repository": "../repo", "permission": "push"},
		{"repository": "owner/repo", "permission": "push"},
		{"repository": "repo", "permission": "push$(id)"},
		{"repository": strings.Repeat("a", 101), "permission": "pull"},
		{"repository": "repo", "permission": "admin"},
		{"repository": "repo", "permission": "push", "command": "gh auth token"},
		{"repository": "repo"},
	}
	for _, arguments := range tests {
		if err := ValidateGitHubArguments(arguments); err == nil {
			t.Fatalf("hostile arguments accepted: %#v", arguments)
		}
	}
}

func TestLikelySecretReasonsFailClosedWithoutBlockingDescriptions(t *testing.T) {
	for _, reason := range []string{
		"ghp_0123456789abcdefghijklmnopqrstuv",            // pragma: allowlist secret
		"github_pat_0123456789abcdefghijklmnopqrstuvwxyz", // pragma: allowlist secret
		"Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
		"password=correct-horse-battery-staple", // pragma: allowlist secret
		"-----BEGIN PRIVATE KEY-----",           // pragma: allowlist secret
		strings.Repeat("A", 80),
	} {
		if err := ValidateReason(reason); err == nil {
			t.Fatalf("likely secret reason accepted: %q", reason)
		}
	}
	for _, reason := range []string{
		"Rotate the CI secret without including its value",
		"Grant access so the maintainer can review pull requests",
		"Investigate commit 0123456789abcdef0123456789abcdef01234567",
	} {
		if err := ValidateReason(reason); err != nil {
			t.Fatalf("ordinary reason rejected %q: %v", reason, err)
		}
	}
}

func TestExpiredObjectsFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	catalog := validCatalog(now.Add(-2 * time.Hour))
	if err := ValidateCatalog(catalog, now, 24*time.Hour); err == nil {
		t.Fatal("expired catalog accepted")
	}
	request := validRequest(now.Add(-2 * time.Hour))
	if err := SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRequest(request, now, 24*time.Hour); err == nil {
		t.Fatal("expired request accepted")
	}
	receipt := validReceipt(now.Add(-2*time.Hour), request)
	if err := ValidateReceipt(receipt, now, 24*time.Hour); err == nil {
		t.Fatal("expired receipt accepted")
	}
}

func TestPersistedEnvelopeValidationRetainsExpiredProtocolHistory(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	catalog := validCatalog(now.Add(-2 * time.Hour))
	if err := ValidatePersistedCatalog(catalog); err != nil {
		t.Fatalf("expired catalog is valid durable history: %v", err)
	}
	request := validRequest(now.Add(-2 * time.Hour))
	if err := SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePersistedRequest(request); err != nil {
		t.Fatalf("expired request is valid durable history: %v", err)
	}
	receipt := validReceipt(now.Add(-2*time.Hour), request)
	if err := ValidatePersistedReceipt(receipt); err != nil {
		t.Fatalf("expired receipt is valid durable history: %v", err)
	}
}

func TestReceiptEvidenceIsDeferredFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	request := validRequest(now)
	if err := SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	receipt := validReceipt(now, request)
	receipt.Evidence = "synthetic-private-material-canary"
	if err := ValidateReceipt(receipt, now, time.Hour); err == nil {
		t.Fatal("free-form receipt evidence accepted")
	}
}

func TestStateTransitions(t *testing.T) {
	if next, err := NextRequestState("pending", DecisionApprove); err != nil || next != "approved" {
		t.Fatalf("approve transition: next=%q err=%v", next, err)
	}
	if next, err := NextRequestState("approved", DecisionExecute); err != nil || next != "manually_executed" {
		t.Fatalf("execute transition: next=%q err=%v", next, err)
	}
	if next, err := NextRequestState("pending", DecisionApproveForExecution); err != nil || next != "approved_for_execution" {
		t.Fatalf("v2 approval transition: next=%q err=%v", next, err)
	}
	if next, err := NextRequestState("approved_for_execution", DecisionExecuted); err != nil || next != "executed" {
		t.Fatalf("v2 execution transition: next=%q err=%v", next, err)
	}
	if next, err := NextRequestState("approved_for_execution", DecisionApproveForExecution); err != nil || next != "approved_for_execution" {
		t.Fatalf("v2 retry approval transition: next=%q err=%v", next, err)
	}
	for _, invalid := range [][2]string{{"pending", DecisionExecute}, {"approved", DecisionDeny}, {"denied", DecisionApprove}, {"manually_executed", DecisionExecute}} {
		if _, err := NextRequestState(invalid[0], invalid[1]); err == nil {
			t.Fatalf("invalid transition accepted: %#v", invalid)
		}
	}
}

func TestReceiptVersionsBindDecisionFamilies(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	request := validRequest(now)
	if err := SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	v2 := Receipt{Version: ReceiptVersionV2, ID: "rec_0123456789abcdefghij", RequestID: request.ID, RequestDigest: request.Digest, Decision: DecisionApproveForExecution, Reviewer: "reviewer@example.invalid", AdapterVersion: AdapterGitHubAddCollaboratorV1, CreatedAt: Timestamp(now), ExpiresAt: Timestamp(now.Add(time.Hour))}
	if err := ValidateReceipt(v2, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	v2.Decision = DecisionApproveForManualExecution
	if err := ValidateReceipt(v2, now, time.Hour); err == nil {
		t.Fatal("v2 accepted v1 manual-execution decision")
	}
	v2.Version = ReceiptVersionV1
	v2.Decision = DecisionExecuted
	if err := ValidateReceipt(v2, now, time.Hour); err == nil {
		t.Fatal("v1 accepted execution-only decision")
	}
	v3 := Receipt{Version: ReceiptVersion, ID: "rec_0123456789abcdefghij", RequestID: request.ID, RequestDigest: request.Digest, Decision: DecisionApproveForExecution, Reviewer: "reviewer@example.invalid", ProfileID: ProfileGitHubCommandID, ProfileVersion: ProfileGitHubCommandVersion, PlanDigest: strings.Repeat("a", 64), CreatedAt: Timestamp(now), ExpiresAt: Timestamp(now.Add(time.Hour))}
	if err := ValidateReceipt(v3, now, time.Hour); err != nil {
		t.Fatal(err)
	}
}

func validCatalog(now time.Time) Catalog {
	return Catalog{
		Version: CatalogVersion, IssuedAt: Timestamp(now), ExpiresAt: Timestamp(now.Add(time.Hour)),
		Profiles: []CommandProfile{{ID: ProfileGitHubCommandID, Version: ProfileGitHubCommandVersion, DisplayName: "GitHub CLI command", AuthorityLabel: "Broad GitHub authority", SandboxLabel: "Ephemeral local state", NetworkLabel: "GitHub network", CWDLabel: "Ephemeral directory", OutputLabel: "Bounded sanitized trusted-local output preview", Limits: ProfileLimits{MaxArgvCount: MaxArgvCount, MaxArgumentBytes: MaxArgumentBytes, MaxAggregateBytes: MaxArgvAggregateBytes}}},
		Capabilities: []Capability{{
			ID: "github:example-owner", DisplayName: "Example GitHub authority",
			Actions:     []string{ActionGitHubAddCollaborator},
			Constraints: GitHubConstraints{Owner: "example-owner", Collaborator: "example-agent", Permissions: []string{"pull", "push"}},
		}},
	}
}

func validRequest(now time.Time) Request {
	return Request{
		Version: RequestVersion, ID: "req_0123456789abcdefghij", ProfileID: ProfileGitHubCommandID, ProfileVersion: ProfileGitHubCommandVersion,
		Argv:   []string{"api", "repos/example-owner/project"},
		Reason: "Allow a bounded contribution", CreatedAt: Timestamp(now), ExpiresAt: Timestamp(now.Add(time.Hour)),
		Nonce: "0123456789abcdefghijklmnopqrstuv",
	}
}

func validReceipt(now time.Time, request Request) Receipt {
	return Receipt{
		Version: ReceiptVersionV1, ID: "rec_0123456789abcdefghij", RequestID: request.ID,
		RequestDigest: request.Digest, Decision: DecisionApprove, Reviewer: "reviewer@example.invalid",
		AdapterVersion: AdapterGitHubAddCollaboratorV1, CreatedAt: Timestamp(now), ExpiresAt: Timestamp(now.Add(time.Hour)),
	}
}
