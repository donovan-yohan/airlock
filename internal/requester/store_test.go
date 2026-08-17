package requester

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/donovan-yohan/airlock/internal/model"
)

func TestStoreCatalogCreateReceiptLifecycle(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	store := newTestStore(t, publicKey, now)
	if err := store.ImportCatalog(testCatalog(t, privateKey, now)); err != nil {
		t.Fatal(err)
	}
	record, err := store.Create(testCreateInput())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "pending" || model.VerifyRequestDigest(record.Request) != nil {
		t.Fatalf("unexpected created record: %#v", record)
	}

	mutated := record
	mutated.Request.Arguments["repository"] = "changed"
	stored, _ := store.Record(record.Request.ID)
	if stored.Request.Arguments["repository"] != "project" {
		t.Fatal("caller mutated immutable stored request")
	}

	approve := testReceipt(t, privateKey, now, record.Request, model.DecisionApprove, "rec_0123456789abcdefghij")
	approved, err := store.AcceptReceipt(approve)
	if err != nil || approved.State != "approved" {
		t.Fatalf("approve state=%q err=%v", approved.State, err)
	}
	if _, err := store.AcceptReceipt(approve); err == nil {
		t.Fatal("replayed receipt accepted")
	}
	execute := testReceipt(t, privateKey, now.Add(time.Minute), record.Request, model.DecisionExecute, "rec_0123456789abcdefghik")
	executed, err := store.AcceptReceipt(execute)
	if err != nil || executed.State != "manually_executed" {
		t.Fatalf("execute state=%q err=%v", executed.State, err)
	}
}

func TestStoreRejectsUnknownMalformedAndInvalidTransitions(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	store := newTestStore(t, publicKey, now)
	if err := store.ImportCatalog(testCatalog(t, privateKey, now)); err != nil {
		t.Fatal(err)
	}

	tests := []CreateInput{
		{CapabilityID: "github:unknown", Action: model.ActionGitHubAddCollaborator, Arguments: map[string]string{"repository": "project", "permission": "push"}, Reason: "reason", TTLSeconds: 600},
		{CapabilityID: "github:example-owner", Action: "shell.run", Arguments: map[string]string{"repository": "project", "permission": "push"}, Reason: "reason", TTLSeconds: 600},
		{CapabilityID: "github:example-owner", Action: model.ActionGitHubAddCollaborator, Arguments: map[string]string{"repository": "../project", "permission": "push"}, Reason: "reason", TTLSeconds: 600},
		{CapabilityID: "github:example-owner", Action: model.ActionGitHubAddCollaborator, Arguments: map[string]string{"repository": "project", "permission": "admin"}, Reason: "reason", TTLSeconds: 600},
		{CapabilityID: "github:example-owner", Action: model.ActionGitHubAddCollaborator, Arguments: map[string]string{"repository": "project", "permission": "push"}, Reason: strings.Repeat("x", model.MaxReasonBytes+1), TTLSeconds: 600},
		{CapabilityID: "github:example-owner", Action: model.ActionGitHubAddCollaborator, Arguments: map[string]string{"repository": "project", "permission": "push"}, Reason: "password=correct-horse-battery-staple", TTLSeconds: 600},
	}
	for _, input := range tests {
		if _, err := store.Create(input); err == nil {
			t.Fatalf("invalid request accepted: %#v", input)
		}
	}

	record, err := store.Create(testCreateInput())
	if err != nil {
		t.Fatal(err)
	}
	execute := testReceipt(t, privateKey, now, record.Request, model.DecisionExecute, "rec_0123456789abcdefghij")
	if _, err := store.AcceptReceipt(execute); err == nil {
		t.Fatal("execute receipt accepted before approval")
	}
	approve := testReceipt(t, privateKey, now, record.Request, model.DecisionApprove, "rec_0123456789abcdefghik")
	approve.RequestDigest = strings.Repeat("0", 64)
	if _, err := store.AcceptReceipt(approve); err == nil {
		t.Fatal("mutated receipt accepted")
	}
}

func TestRecordPageIsBoundedStableAndRejectsUnknownCursor(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	store := newTestStore(t, publicKey, now)
	if err := store.ImportCatalog(testCatalog(t, privateKey, now)); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := store.Create(testCreateInput()); err != nil {
			t.Fatal(err)
		}
	}
	first, cursor, err := store.RecordPage(2, "")
	if err != nil || len(first) != 2 || cursor == "" {
		t.Fatalf("first page=%d cursor=%q err=%v", len(first), cursor, err)
	}
	second, next, err := store.RecordPage(2, cursor)
	if err != nil || len(second) != 1 || next != "" || first[0].Request.ID == second[0].Request.ID || first[1].Request.ID == second[0].Request.ID {
		t.Fatalf("second page=%#v next=%q err=%v", second, next, err)
	}
	if _, _, err := store.RecordPage(MaxRecordPage+1, ""); err == nil {
		t.Fatal("oversized page accepted")
	}
	if _, _, err := store.RecordPage(1, "req_unknown"); err == nil {
		t.Fatal("unknown cursor accepted")
	}
}

func TestRequesterHomePageIsBounded(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	store := &Store{state: persistedState{Requests: make(map[string]Record)}}
	for index := 0; index < DefaultRecordPage+10; index++ {
		id := fmt.Sprintf("req_%020d", index)
		store.state.Requests[id] = Record{
			Request: model.Request{ID: id, CreatedAt: model.Timestamp(now.Add(time.Duration(index) * time.Second))},
			State:   "pending",
		}
	}
	handler := NewServer(store).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("requester home status=%d body=%q", response.Code, response.Body.String())
	}
	if got := strings.Count(response.Body.String(), `class="state"`); got != DefaultRecordPage {
		t.Fatalf("requester home rendered %d records, want %d", got, DefaultRecordPage)
	}
	if !strings.Contains(response.Body.String(), "Older requests") {
		t.Fatal("bounded requester home omitted next-page link")
	}
	for _, target := range []string{"/?unexpected=1", "/?cursor=req_unknown"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("requester home accepted invalid query %q: status=%d", target, response.Code)
		}
	}
}

func TestRequesterStoreBoundsGrowthButStillAcceptsExistingReceipts(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store := newTestStore(t, publicKey, now)
	if err := store.ImportCatalog(testCatalog(t, privateKey, now)); err != nil {
		t.Fatal(err)
	}
	record, err := store.Create(testCreateInput())
	if err != nil {
		t.Fatal(err)
	}
	for index := len(store.state.Requests); index < maxRequesterRequests; index++ {
		id := fmt.Sprintf("req_fill_%020d", index)
		store.state.Requests[id] = Record{Request: model.Request{ExpiresAt: model.Timestamp(now.Add(time.Minute))}}
	}
	if _, err := store.Create(testCreateInput()); err == nil || !strings.Contains(err.Error(), "store is full") {
		t.Fatalf("full requester store accepted a request: %v", err)
	}
	receipt := testReceipt(t, privateKey, now, record.Request, model.DecisionApprove, "rec_0123456789abcdefghij")
	updated, err := store.AcceptReceipt(receipt)
	if err != nil || updated.State != "approved" {
		t.Fatalf("full requester store rejected an existing receipt: state=%q err=%v", updated.State, err)
	}
}

func TestMaximumRequesterRecordCountFitsAtomicStateFile(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := newTestStore(t, publicKey, time.Now().UTC())
	state := persistedState{Requests: make(map[string]Record, maxRequesterRequests)}
	timestamp := "2026-08-14T12:00:00Z"
	for index := range maxRequesterRequests {
		requestID := fmt.Sprintf("req_%080d", index)
		request := model.Request{
			Version: model.RequestVersion, ID: requestID, CapabilityID: strings.Repeat("a", 128),
			Action:    model.ActionGitHubAddCollaborator,
			Arguments: map[string]string{"repository": strings.Repeat("r", 100), "permission": "push"},
			Reason:    strings.Repeat("r", model.MaxReasonBytes), CreatedAt: timestamp, ExpiresAt: timestamp,
			Nonce: strings.Repeat("n", 96), Digest: strings.Repeat("d", 64),
		}
		receipts := make([]model.Receipt, 2)
		for receiptIndex := range receipts {
			receipts[receiptIndex] = model.Receipt{
				Version: model.ReceiptVersion, ID: fmt.Sprintf("rec_%080d", index*2+receiptIndex),
				RequestID: requestID, RequestDigest: request.Digest,
				Decision: []string{model.DecisionApprove, model.DecisionExecute}[receiptIndex],
				Reviewer: strings.Repeat("r", 254), AdapterVersion: model.AdapterGitHubAddCollaboratorV1,
				CreatedAt: timestamp, ExpiresAt: timestamp, Signature: strings.Repeat("s", 88),
			}
		}
		state.Requests[requestID] = Record{Request: request, State: "manually_executed", Receipts: receipts}
	}
	if err := store.commit(state); err != nil {
		t.Fatalf("maximum bounded requester state exceeded the atomic state-file ceiling: %v", err)
	}
}

func TestRequesterStoreRecoversAfterTTLTighteningAndKeyRotation(t *testing.T) {
	oldPublic, oldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("TTL tightening", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := NewStore(dir, oldPublic, 15*time.Minute, time.Hour, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		store.now = func() time.Time { return now }
		if err := store.ImportCatalog(testCatalog(t, oldPrivate, now)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Create(testCreateInput()); err != nil {
			t.Fatal(err)
		}
		recovered, err := NewStore(dir, oldPublic, 5*time.Minute, time.Hour, time.Hour)
		if err != nil {
			t.Fatalf("TTL tightening caused a startup failure: %v", err)
		}
		if len(recovered.state.Requests) != 0 || recovered.state.Catalog == nil {
			t.Fatalf("TTL recovery did not prune only the overlong request: %#v", recovered.state)
		}
		persisted, err := NewStore(dir, oldPublic, 5*time.Minute, time.Hour, time.Hour)
		if err != nil || len(persisted.state.Requests) != 0 {
			t.Fatalf("recovered TTL state was not persisted: requests=%d err=%v", len(persisted.state.Requests), err)
		}
	})

	t.Run("trusted key rotation", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := NewStore(dir, oldPublic, 15*time.Minute, time.Hour, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		store.now = func() time.Time { return now }
		if err := store.ImportCatalog(testCatalog(t, oldPrivate, now)); err != nil {
			t.Fatal(err)
		}
		record, err := store.Create(testCreateInput())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.AcceptReceipt(testReceipt(t, oldPrivate, now, record.Request, model.DecisionApprove, "rec_0123456789abcdefghij")); err != nil {
			t.Fatal(err)
		}
		recovered, err := NewStore(dir, newPublic, 15*time.Minute, time.Hour, time.Hour)
		if err != nil {
			t.Fatalf("trusted key rotation caused a startup failure: %v", err)
		}
		if recovered.state.Catalog != nil || len(recovered.state.Requests) != 0 {
			t.Fatalf("key rotation retained state signed by the old key: %#v", recovered.state)
		}
	})
}

func TestRequesterAcceptsTimelyReceiptDeliveredAfterRequestExpiry(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	store := newTestStore(t, publicKey, now)
	if err := store.ImportCatalog(testCatalog(t, privateKey, now)); err != nil {
		t.Fatal(err)
	}
	input := testCreateInput()
	input.TTLSeconds = 60
	record, err := store.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	receipt := testReceipt(t, privateKey, now.Add(30*time.Second), record.Request, model.DecisionApprove, "rec_0123456789abcdefghij")
	store.now = func() time.Time { return now.Add(90 * time.Second) }
	updated, err := store.AcceptReceipt(receipt)
	if err != nil || updated.State != "approved" {
		t.Fatalf("timely receipt delivered after request expiry was rejected: state=%q err=%v", updated.State, err)
	}
}

func TestRequesterUIIsReadOnlyAndDoesNotExposePrivateKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store := newTestStore(t, publicKey, now)
	if err := store.ImportCatalog(testCatalog(t, privateKey, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(testCreateInput()); err != nil {
		t.Fatal(err)
	}
	server := NewServer(store)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK || strings.Contains(body, "<form") || strings.Contains(strings.ToLower(body), "approve") {
		t.Fatalf("requester UI is not read-only: code=%d body=%q", response.Code, body)
	}
	privateCanary := base64.RawStdEncoding.EncodeToString(privateKey)
	if strings.Contains(body, privateCanary) {
		t.Fatal("requester UI exposed private key material")
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/requests/not-real/approve", strings.NewReader(""))
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected approval surface status: %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodDelete, "/api/v1/requests", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method status=%d", response.Code)
	}
}

func newTestStore(t *testing.T, publicKey ed25519.PublicKey, now time.Time) *Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dir, publicKey, 15*time.Minute, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	return store
}

func testCatalog(t *testing.T, privateKey ed25519.PrivateKey, now time.Time) model.Catalog {
	t.Helper()
	catalog := model.Catalog{
		Version: model.CatalogVersion, IssuedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(time.Hour)),
		Capabilities: []model.Capability{{
			ID: "github:example-owner", DisplayName: "Example GitHub authority",
			Actions:     []string{model.ActionGitHubAddCollaborator},
			Constraints: model.GitHubConstraints{Owner: "example-owner", Collaborator: "example-agent", Permissions: []string{"pull", "push"}},
		}},
	}
	if err := model.SignCatalog(&catalog, privateKey); err != nil {
		t.Fatal(err)
	}
	return catalog
}

func testCreateInput() CreateInput {
	return CreateInput{
		CapabilityID: "github:example-owner", Action: model.ActionGitHubAddCollaborator,
		Arguments: map[string]string{"repository": "project", "permission": "push"},
		Reason:    "Enable a bounded contribution", TTLSeconds: 600,
	}
}

func testReceipt(t *testing.T, privateKey ed25519.PrivateKey, now time.Time, request model.Request, decision, id string) model.Receipt {
	t.Helper()
	receipt := model.Receipt{
		Version: model.ReceiptVersion, ID: id, RequestID: request.ID, RequestDigest: request.Digest,
		Decision: decision, Reviewer: "reviewer@example.invalid", AdapterVersion: model.AdapterGitHubAddCollaboratorV1,
		CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(time.Hour)),
	}
	if err := model.SignReceipt(&receipt, privateKey); err != nil {
		t.Fatal(err)
	}
	return receipt
}
