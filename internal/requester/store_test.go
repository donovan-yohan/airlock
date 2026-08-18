package requester

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
	mutated.Request.Argv[0] = "changed"
	stored, _ := store.Record(record.Request.ID)
	if stored.Request.Argv[0] != "api" {
		t.Fatal("caller mutated immutable stored request")
	}

	approve := testReceipt(t, privateKey, now, record.Request, model.DecisionApproveForExecution, "rec_0123456789abcdefghij")
	approved, err := store.AcceptReceipt(approve)
	if err != nil || approved.State != "approved_for_execution" {
		t.Fatalf("approve state=%q err=%v", approved.State, err)
	}
	if _, err := store.AcceptReceipt(approve); err == nil {
		t.Fatal("replayed receipt accepted")
	}
	execute := testReceipt(t, privateKey, now.Add(time.Minute), record.Request, model.DecisionExecuted, "rec_0123456789abcdefghik")
	executed, err := store.AcceptReceipt(execute)
	if err != nil || executed.State != "executed" {
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
		{ProfileID: "unknown", ProfileVersion: "v1", Argv: []string{"api"}, Reason: "reason", TTLSeconds: 600},
		{ProfileID: model.ProfileShellRunID, ProfileVersion: model.ProfileShellRunVersion, Argv: []string{"echo"}, Reason: "reason", TTLSeconds: 600},
		{ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion, Argv: []string{"api", "bad\nvalue"}, Reason: "reason", TTLSeconds: 600},
		{ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion, Argv: []string{}, Reason: "reason", TTLSeconds: 600},
		{ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion, Argv: []string{"api"}, Reason: strings.Repeat("x", model.MaxReasonBytes+1), TTLSeconds: 600},
		{ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion, Argv: []string{"api"}, Reason: " \t ", TTLSeconds: 600},
		{ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion, Argv: []string{"api"}, Reason: "password=correct-horse-battery-staple", TTLSeconds: 600},
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
	execute := testReceipt(t, privateKey, now, record.Request, model.DecisionExecuted, "rec_0123456789abcdefghij")
	if _, err := store.AcceptReceipt(execute); err == nil {
		t.Fatal("execute receipt accepted before approval")
	}
	approve := testReceipt(t, privateKey, now, record.Request, model.DecisionApproveForExecution, "rec_0123456789abcdefghik")
	approve.RequestDigest = strings.Repeat("0", 64)
	if _, err := store.AcceptReceipt(approve); err == nil {
		t.Fatal("mutated receipt accepted")
	}
}

func TestRequesterAPIRejectsTrustedExecutionFieldInjection(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store := newTestStore(t, publicKey, now)
	if err := store.ImportCatalog(testCatalog(t, privateKey, now)); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"profile_id":"github.command","profile_version":"v1","argv":["api","user"],"reason":"review exact argv","ttl_seconds":600,"executable":"/tmp/requester-gh","env":{"GH_TOKEN":"requester"},"cwd":"/tmp/requester","credentials":"requester","identity":"requester","timeout_seconds":9999,"sandbox":"none"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/requests", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	NewServer(store).Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("trusted execution field injection status=%d body=%q", response.Code, response.Body.String())
	}
	if len(store.state.Requests) != 0 {
		t.Fatal("trusted execution field injection reached durable requester state")
	}
}

func TestRequesterRejectsCredentialArgvWithoutStateOrResponseEgress(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store := newTestStore(t, publicKey, now)
	if err := store.ImportCatalog(testCatalog(t, privateKey, now)); err != nil {
		t.Fatal(err)
	}
	secretArgv := "Authorization: Bearer " + strings.Repeat("a", 20)
	payload := []byte(fmt.Sprintf(`{"profile_id":"github.command","profile_version":"v1","argv":["api",%q],"reason":"review exact argv","ttl_seconds":600}`, secretArgv))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/requests", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server := NewServer(store)
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("credential argv status=%d", response.Code)
	}
	if strings.Contains(response.Body.String(), secretArgv) {
		t.Fatal("credential argv appeared in requester rejection")
	}
	if len(store.state.Requests) != 0 {
		t.Fatal("credential argv reached durable requester state")
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if strings.Contains(response.Body.String(), secretArgv) {
		t.Fatal("credential argv appeared in requester UI")
	}
}

func TestRequesterAPIRejectsDuplicateProposalFields(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store := newTestStore(t, publicKey, now)
	if err := store.ImportCatalog(testCatalog(t, privateKey, now)); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"profile_id":"github.command","profile_version":"v1","argv":["api","user"],"argv":["auth","token"],"reason":"review exact argv","ttl_seconds":600}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/requests", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	NewServer(store).Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate proposal field status=%d body=%q", response.Code, response.Body.String())
	}
	if len(store.state.Requests) != 0 {
		t.Fatal("ambiguous proposal reached durable requester state")
	}
}

func TestRequesterRejectsReceiptProtocolAndResolvedPlanDrift(t *testing.T) {
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

	legacy := testReceipt(t, privateKey, now, record.Request, model.DecisionApproveForExecution, "rec_0123456789abcdefghij")
	legacy.Version = model.ReceiptVersionV2
	legacy.ProfileID, legacy.ProfileVersion, legacy.PlanDigest = "", "", ""
	legacy.AdapterVersion = model.AdapterGitHubAddCollaboratorV1
	legacy.Signature = ""
	if err := model.SignReceipt(&legacy, privateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptReceipt(legacy); err == nil {
		t.Fatal("legacy execution receipt accepted for a current command request")
	}

	approval := testReceipt(t, privateKey, now, record.Request, model.DecisionApproveForExecution, "rec_0123456789abcdefghik")
	if _, err := store.AcceptReceipt(approval); err != nil {
		t.Fatal(err)
	}
	execution := testReceipt(t, privateKey, now.Add(time.Second), record.Request, model.DecisionExecuted, "rec_0123456789abcdefghil")
	execution.PlanDigest = strings.Repeat("b", 64)
	execution.Signature = ""
	if err := model.SignReceipt(&execution, privateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptReceipt(execution); err == nil {
		t.Fatal("execution receipt with a different resolved plan was accepted")
	}

	tampered := clonePersistedState(store.state)
	tamperedRecord := tampered.Requests[record.Request.ID]
	tamperedRecord.State = "executed"
	tamperedRecord.Receipts = append(tamperedRecord.Receipts, execution)
	tampered.Requests[record.Request.ID] = tamperedRecord
	if err := store.commit(tampered); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(filepath.Dir(store.path), publicKey, 15*time.Minute, time.Hour, time.Hour); err == nil {
		t.Fatal("persisted request with receipt plan drift was silently recovered")
	}
	after, err := os.ReadFile(store.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("invalid requester state was rewritten: err=%v", err)
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

func TestPendingRequestSyncEndpointIsCursorPaged(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	store := &Store{now: func() time.Time { return now }, state: persistedState{Requests: make(map[string]Record)}}
	for index := 0; index < 20; index++ {
		id := fmt.Sprintf("req_%020d", index)
		store.state.Requests[id] = Record{Request: model.Request{
			ID: id, CreatedAt: model.Timestamp(now.Add(-time.Duration(index) * time.Second)), ExpiresAt: model.Timestamp(now.Add(time.Hour)),
		}, State: "pending"}
	}
	handler := NewServer(store).Handler()
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/v1/pending-requests?limit=7", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first pending page status=%d body=%q", first.Code, first.Body.String())
	}
	var page1 pendingRequestPageResponse
	if err := json.Unmarshal(first.Body.Bytes(), &page1); err != nil || len(page1.Requests) != 7 || page1.NextCursor == "" {
		t.Fatalf("first pending page=%#v err=%v", page1, err)
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/api/v1/pending-requests?limit=7&cursor="+url.QueryEscape(page1.NextCursor), nil))
	var page2 pendingRequestPageResponse
	if err := json.Unmarshal(second.Body.Bytes(), &page2); err != nil || second.Code != http.StatusOK || len(page2.Requests) != 7 {
		t.Fatalf("second pending page status=%d page=%#v err=%v", second.Code, page2, err)
	}
	seen := make(map[string]struct{}, 14)
	for _, request := range append(page1.Requests, page2.Requests...) {
		if _, duplicate := seen[request.ID]; duplicate {
			t.Fatalf("pending cursor repeated request %q", request.ID)
		}
		seen[request.ID] = struct{}{}
	}
	invalid := httptest.NewRecorder()
	handler.ServeHTTP(invalid, httptest.NewRequest(http.MethodGet, "/api/v1/pending-requests?limit=101", nil))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("oversized pending page status=%d", invalid.Code)
	}
}

func TestMaximumPendingSyncPageFitsTrustedResponseBudget(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	store := &Store{now: func() time.Time { return now }, state: persistedState{Requests: make(map[string]Record)}}
	for index := 0; index < 17; index++ {
		request := maximalEscapableRequest(t, now.Add(-time.Duration(index)*time.Second), fmt.Sprintf("req_%020d", index))
		store.state.Requests[request.ID] = Record{Request: request, State: "pending"}
	}
	response := httptest.NewRecorder()
	NewServer(store).Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/pending-requests?limit=16", nil))
	var page pendingRequestPageResponse
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || response.Code != http.StatusOK || len(page.Requests) != 16 || page.NextCursor == "" || response.Body.Len() > 2<<20 {
		t.Fatalf("maximum pending page status=%d bytes=%d records=%d cursor=%q err=%v", response.Code, response.Body.Len(), len(page.Requests), page.NextCursor, err)
	}
	t.Logf("maximum pending sync page bytes=%d", response.Body.Len())
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
	receipt := testReceipt(t, privateKey, now, record.Request, model.DecisionApproveForExecution, "rec_0123456789abcdefghij")
	updated, err := store.AcceptReceipt(receipt)
	if err != nil || updated.State != "approved_for_execution" {
		t.Fatalf("full requester store rejected an existing receipt: state=%q err=%v", updated.State, err)
	}
}

func TestRequesterStateBudgetUsesLiteralEscapableArgvAndLeavesReceiptHeadroom(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dir, publicKey, time.Hour, 24*time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	catalog := maximalCatalog(t, privateKey, now)
	if err := store.ImportCatalog(catalog); err != nil {
		t.Fatalf("maximal catalog import: %v", err)
	}

	state := clonePersistedState(store.state)
	state.Requests = make(map[string]Record, maxRequesterRequests)
	for index := range maxRequesterRequests {
		request := maximalEscapableRequest(t, now, fmt.Sprintf("req_%020d", index))
		receipts := maximalRequesterReceipts(t, privateKey, now, request, index, maxRequesterReceipts-1)
		state.Requests[request.ID] = Record{Request: request, State: "approved_for_execution", Receipts: receipts}
	}
	if err := store.commit(state); err != nil {
		t.Fatalf("maximal requester state exceeded the atomic state-file ceiling: %v", err)
	}
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 14<<20 || !bytes.Contains(raw, []byte(`\"`)) || !bytes.Contains(raw, []byte(`\\`)) {
		t.Fatalf("state budget lacked worst-case JSON escaping headroom: bytes=%d", len(raw))
	}
	if _, err := store.Create(testCreateInput()); err == nil || !strings.Contains(err.Error(), "store is full") {
		t.Fatalf("count cap did not bind before state-file bytes: %v", err)
	}

	first := state.Requests[fmt.Sprintf("req_%020d", 0)]
	executed := testReceipt(t, privateKey, now.Add(time.Duration(maxRequesterReceipts-1)*time.Second), first.Request, model.DecisionExecuted, "rec_receipt_headroom_0001")
	if _, err := store.AcceptReceipt(executed); err != nil {
		t.Fatalf("full requester store refused a valid receipt for an existing record: %v", err)
	}
	maximized := clonePersistedState(store.state)
	for index := 1; index < maxRequesterRequests; index++ {
		id := fmt.Sprintf("req_%020d", index)
		record := maximized.Requests[id]
		record.Receipts = append(record.Receipts, maximalRequesterReceipts(t, privateKey, now, record.Request, index, maxRequesterReceipts)[maxRequesterReceipts-1])
		record.State = model.DecisionExecuted
		maximized.Requests[id] = record
	}
	if err := store.commit(maximized); err != nil {
		t.Fatalf("maximal receipt histories exceeded the atomic state-file ceiling: %v", err)
	}
	laterCatalog := maximalCatalog(t, privateKey, now.Add(time.Second))
	if err := store.ImportCatalog(laterCatalog); err != nil {
		t.Fatalf("catalog import at full requester occupancy: %v", err)
	}
	raw, err = os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 14<<20 || !bytes.Contains(raw, []byte(`\"`)) || !bytes.Contains(raw, []byte(`\\`)) {
		t.Fatalf("maximal requester state lacked JSON-escape headroom: bytes=%d", len(raw))
	}
	t.Logf("maximum requester worst-case escaped state bytes=%d", len(raw))
	restarted, err := NewStore(dir, publicKey, time.Hour, 24*time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("maximal requester state did not restart: %v", err)
	}
	if record, found := restarted.Record(first.Request.ID); !found || record.State != model.DecisionExecuted || len(record.Receipts) != maxRequesterReceipts {
		t.Fatalf("receipt headroom was not durable: found=%v record=%#v", found, record)
	}
	if catalog, found := restarted.Catalog(); !found || catalog.IssuedAt != laterCatalog.IssuedAt {
		t.Fatalf("catalog import did not survive maximal-state restart: found=%v catalog=%#v", found, catalog)
	}
}

func TestRequesterStorePreservesHistoryAfterTTLTighteningAndKeyRotation(t *testing.T) {
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
		if len(recovered.state.Requests) != 1 || recovered.state.Catalog == nil {
			t.Fatalf("TTL tightening erased valid durable history: %#v", recovered.state)
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
		if _, err := store.AcceptReceipt(testReceipt(t, oldPrivate, now, record.Request, model.DecisionApproveForExecution, "rec_0123456789abcdefghij")); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(filepath.Join(dir, "requester-state.json"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewStore(dir, newPublic, 15*time.Minute, time.Hour, time.Hour); err == nil {
			t.Fatal("trusted key rotation silently discarded old signed state")
		}
		after, err := os.ReadFile(filepath.Join(dir, "requester-state.json"))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("key rotation rewrote durable requester history: err=%v", err)
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
	receipt := testReceipt(t, privateKey, now.Add(30*time.Second), record.Request, model.DecisionApproveForExecution, "rec_0123456789abcdefghij")
	store.now = func() time.Time { return now.Add(90 * time.Second) }
	updated, err := store.AcceptReceipt(receipt)
	if err != nil || updated.State != "approved_for_execution" {
		t.Fatalf("timely receipt delivered after request expiry was rejected: state=%q err=%v", updated.State, err)
	}
}

func TestLegacyCatalogRequestsAndV1V2ReceiptsRemainReadableButFailClosedForCreation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dir, publicKey, 15*time.Minute, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	legacyCatalog := testCatalog(t, privateKey, now)
	legacyCatalog.Version = model.CatalogVersionV1
	legacyCatalog.Profiles = nil
	legacyCatalog.Signature = ""
	if err := model.SignCatalog(&legacyCatalog, privateKey); err != nil {
		t.Fatal(err)
	}
	if err := store.ImportCatalog(legacyCatalog); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(testCreateInput()); err == nil || !strings.Contains(err.Error(), "does not support command proposals") {
		t.Fatalf("legacy catalog allowed a current command proposal: %v", err)
	}

	legacyRequest := func(id string) model.Request {
		request := model.Request{
			Version: model.RequestVersionV1, ID: id, CapabilityID: "github:example-owner", Action: model.ActionGitHubAddCollaborator,
			Arguments: map[string]string{"repository": "project", "permission": "push"}, Reason: "Historical request",
			CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(10 * time.Minute)), Nonce: "0123456789abcdefghijklmnopqrstuv",
		}
		if err := model.SetRequestDigest(&request); err != nil {
			t.Fatal(err)
		}
		return request
	}
	signedReceipt := func(request model.Request, version, decision, id string, created time.Time) model.Receipt {
		receipt := model.Receipt{
			Version: version, ID: id, RequestID: request.ID, RequestDigest: request.Digest, Decision: decision,
			Reviewer: "reviewer@example.invalid", AdapterVersion: model.AdapterGitHubAddCollaboratorV1,
			CreatedAt: model.Timestamp(created), ExpiresAt: model.Timestamp(created.Add(time.Hour)),
		}
		if err := model.SignReceipt(&receipt, privateKey); err != nil {
			t.Fatal(err)
		}
		return receipt
	}
	manualRequest := legacyRequest("req_0123456789abcdefghij")
	manualReceipts := []model.Receipt{
		signedReceipt(manualRequest, model.ReceiptVersionV1, model.DecisionApproveForManualExecution, "rec_0123456789abcdefghij", now),
		signedReceipt(manualRequest, model.ReceiptVersionV1, model.DecisionManuallyExecuted, "rec_0123456789abcdefghik", now.Add(time.Second)),
	}
	executedRequest := legacyRequest("req_0123456789abcdefghik")
	executionReceipts := []model.Receipt{
		signedReceipt(executedRequest, model.ReceiptVersionV2, model.DecisionApproveForExecution, "rec_0123456789abcdefghil", now),
		signedReceipt(executedRequest, model.ReceiptVersionV2, model.DecisionExecuted, "rec_0123456789abcdefghim", now.Add(time.Second)),
	}
	state := clonePersistedState(store.state)
	state.Requests[manualRequest.ID] = Record{Request: manualRequest, State: "manually_executed", Receipts: manualReceipts}
	state.Requests[executedRequest.ID] = Record{Request: executedRequest, State: "executed", Receipts: executionReceipts}
	if err := store.commit(state); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewStore(dir, publicKey, 15*time.Minute, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for id, wantState := range map[string]string{manualRequest.ID: "manually_executed", executedRequest.ID: "executed"} {
		record, found := recovered.Record(id)
		if !found || record.State != wantState || len(record.Receipts) != 2 {
			t.Fatalf("historical record %s was not recovered: %#v", id, record)
		}
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
		Profiles: []model.CommandProfile{testCommandProfile()},
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

func maximalCatalog(t *testing.T, privateKey ed25519.PrivateKey, now time.Time) model.Catalog {
	t.Helper()
	catalog := testCatalog(t, privateKey, now)
	catalog.Profiles[0] = model.CommandProfile{
		ID: model.ProfileGitHubCommandID, Version: model.ProfileGitHubCommandVersion,
		DisplayName: strings.Repeat(`"`, 200), AuthorityLabel: strings.Repeat(`"`, 200), SandboxLabel: strings.Repeat(`"`, 200),
		NetworkLabel: strings.Repeat(`"`, 200), CWDLabel: strings.Repeat(`"`, 200), OutputLabel: strings.Repeat(`"`, 200),
		Limits: model.ProfileLimits{MaxArgvCount: model.MaxArgvCount, MaxArgumentBytes: model.MaxArgumentBytes, MaxAggregateBytes: model.MaxArgvAggregateBytes},
	}
	catalog.Capabilities = make([]model.Capability, 0, model.MaxCapabilities)
	for index := range model.MaxCapabilities {
		owner := fmt.Sprintf("owner%02d", index)
		catalog.Capabilities = append(catalog.Capabilities, model.Capability{
			ID: fmt.Sprintf("github:%s", owner), DisplayName: strings.Repeat(`"`, 100),
			Actions:     []string{model.ActionGitHubAddCollaborator},
			Constraints: model.GitHubConstraints{Owner: owner, Collaborator: fmt.Sprintf("agent%02d", index), Permissions: []string{"pull", "push"}},
		})
	}
	catalog.Signature = ""
	if err := model.SignCatalog(&catalog, privateKey); err != nil {
		t.Fatal(err)
	}
	return catalog
}

func maximalRequesterReceipts(t *testing.T, privateKey ed25519.PrivateKey, now time.Time, request model.Request, requestIndex, count int) []model.Receipt {
	t.Helper()
	receipts := make([]model.Receipt, count)
	for receiptIndex := range receipts {
		decision := model.DecisionApproveForExecution
		if receiptIndex == maxRequesterReceipts-1 {
			decision = model.DecisionExecuted
		}
		receipt := testReceipt(t, privateKey, now.Add(time.Duration(receiptIndex)*time.Second), request, decision, fmt.Sprintf("rec_%020d", requestIndex*maxRequesterReceipts+receiptIndex))
		receipt.Reviewer = strings.Repeat(`"\`, 127)
		receipt.Signature = ""
		if err := model.SignReceipt(&receipt, privateKey); err != nil {
			t.Fatal(err)
		}
		receipts[receiptIndex] = receipt
	}
	return receipts
}

func maximalEscapableRequest(t *testing.T, now time.Time, id string) model.Request {
	t.Helper()
	argv := make([]string, model.MaxArgvCount)
	for index := range argv {
		argv[index] = strings.Repeat(`"\`, model.MaxArgvAggregateBytes/(2*model.MaxArgvCount))
	}
	request := model.Request{
		Version: model.RequestVersion, ID: id, ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion,
		Argv: argv, Reason: strings.Repeat(`"\`, model.MaxReasonBytes/2), CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(time.Hour)),
		Nonce: "0123456789abcdefghijklmnopqrstuv",
	}
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	return request
}

func testCreateInput() CreateInput {
	return CreateInput{
		ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion,
		Argv:   []string{"api", "repos/example-owner/project"},
		Reason: "Enable a bounded contribution", TTLSeconds: 600,
	}
}

func testReceipt(t *testing.T, privateKey ed25519.PrivateKey, now time.Time, request model.Request, decision, id string) model.Receipt {
	t.Helper()
	version := model.ReceiptVersion
	if decision == model.DecisionApproveForManualExecution || decision == model.DecisionManuallyExecuted {
		version = model.ReceiptVersionV1
	}
	receipt := model.Receipt{
		Version: version, ID: id, RequestID: request.ID, RequestDigest: request.Digest,
		Decision: decision, Reviewer: "reviewer@example.invalid", ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion, PlanDigest: strings.Repeat("a", 64),
		CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(time.Hour)),
	}
	if version == model.ReceiptVersionV1 {
		receipt.ProfileID, receipt.ProfileVersion, receipt.PlanDigest = "", "", ""
		receipt.AdapterVersion = model.AdapterGitHubAddCollaboratorV1
	}
	if err := model.SignReceipt(&receipt, privateKey); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func testCommandProfile() model.CommandProfile {
	return model.CommandProfile{ID: model.ProfileGitHubCommandID, Version: model.ProfileGitHubCommandVersion, DisplayName: "GitHub CLI command", AuthorityLabel: "Broad GitHub authority", SandboxLabel: "Ephemeral local state", NetworkLabel: "GitHub network", CWDLabel: "Ephemeral directory", OutputLabel: "Bounded sanitized trusted-local output preview", Limits: model.ProfileLimits{MaxArgvCount: model.MaxArgvCount, MaxArgumentBytes: model.MaxArgumentBytes, MaxAggregateBytes: model.MaxArgvAggregateBytes}}
}
