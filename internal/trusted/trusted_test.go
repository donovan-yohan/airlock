package trusted

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/donovan-yohan/airlock/internal/config"
	"github.com/donovan-yohan/airlock/internal/model"
	"github.com/donovan-yohan/airlock/internal/paging"
	"github.com/donovan-yohan/airlock/internal/requester"
)

func TestAdapterDerivesOnlyTheLocallyTypedCommand(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	request := trustedTestRequest(t, now)
	command, version, err := validateAndRender(request, trustedTestCapabilities(), now, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	want := "gh api --method PUT repos/example-owner/project/collaborators/example-agent -f permission=push --silent"
	if command != want || version != model.AdapterGitHubAddCollaboratorV1 {
		t.Fatalf("command=%q version=%q", command, version)
	}

	mutated := request
	mutated.Arguments = map[string]string{"repository": "project;id", "permission": "push"}
	if _, _, err := validateAndRender(mutated, trustedTestCapabilities(), now, 15*time.Minute); err == nil {
		t.Fatal("mutated hostile request rendered")
	}
	unknown := request
	unknown.CapabilityID = "github:unknown"
	if err := model.SetRequestDigest(&unknown); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateAndRender(unknown, trustedTestCapabilities(), now, 15*time.Minute); err == nil {
		t.Fatal("unknown capability rendered")
	}
	mutatedAuthority := trustedTestCapabilities()
	mutatedAuthority[0].Owner = "-invalid-owner"
	if _, _, err := validateAndRender(request, mutatedAuthority, now, 15*time.Minute); err == nil {
		t.Fatal("invalid locally configured owner rendered")
	}
}

func TestAdapterUsesConfiguredAuthorityIdentities(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	request := trustedTestRequest(t, now)
	request.CapabilityID = "github:other-owner"
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	capabilities := trustedTestCapabilities()
	capabilities[0].ID = request.CapabilityID
	capabilities[0].Owner = "other-owner"
	capabilities[0].Collaborator = "other-agent"

	command, _, err := validateAndRender(request, capabilities, now, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	want := "gh api --method PUT repos/other-owner/project/collaborators/other-agent -f permission=push --silent"
	if command != want {
		t.Fatalf("command=%q want=%q", command, want)
	}
}

func TestTrustedIdentityCSRFMethodsAndReceiptBinding(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store := trustedTestStore(t, privateKey, now)
	requestObject := trustedTestRequest(t, now)
	if err := store.Ingest(requestObject); err != nil {
		t.Fatal(err)
	}

	production, err := NewServer(store, []string{"reviewer@example.invalid"}, false)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, production.Handler(), http.MethodGet, "/", nil, nil, http.StatusUnauthorized)
	assertStatus(t, production.Handler(), http.MethodGet, "/", nil, map[string]string{"X-Airlock-Dev-Identity": "reviewer@example.invalid"}, http.StatusUnauthorized)
	assertStatus(t, production.Handler(), http.MethodGet, "/", nil, map[string]string{"Tailscale-User-Login": "attacker@example.invalid"}, http.StatusUnauthorized)
	assertStatus(t, production.Handler(), http.MethodGet, "/", nil, map[string]string{"Tailscale-User-Login": "reviewer@example.invalid"}, http.StatusOK)
	remoteSpoof := httptest.NewRequest(http.MethodGet, "/", nil)
	remoteSpoof.Header.Set("Tailscale-User-Login", "reviewer@example.invalid")
	remoteSpoof.RemoteAddr = "192.0.2.10:1234"
	remoteResponse := httptest.NewRecorder()
	production.Handler().ServeHTTP(remoteResponse, remoteSpoof)
	if remoteResponse.Code != http.StatusUnauthorized {
		t.Fatalf("non-loopback identity header accepted: %d", remoteResponse.Code)
	}
	duplicate := httptest.NewRequest(http.MethodGet, "/", nil)
	duplicate.RemoteAddr = "127.0.0.1:1234"
	duplicate.Header.Add("Tailscale-User-Login", "reviewer@example.invalid")
	duplicate.Header.Add("Tailscale-User-Login", "reviewer@example.invalid")
	duplicateResponse := httptest.NewRecorder()
	production.Handler().ServeHTTP(duplicateResponse, duplicate)
	if duplicateResponse.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate identity headers accepted: %d", duplicateResponse.Code)
	}

	development, err := NewServer(store, []string{"reviewer@example.invalid"}, true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/requests/"+requestObject.ID, nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
	response := httptest.NewRecorder()
	development.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("review status=%d body=%q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, required := range []string{requestObject.Digest, requestObject.Action, requestObject.ExpiresAt, requestObject.Reason, "gh api --method PUT"} {
		if !strings.Contains(body, required) {
			t.Fatalf("review UI omitted %q", required)
		}
	}
	privateCanary := base64.RawStdEncoding.EncodeToString(privateKey)
	if strings.Contains(body, privateCanary) {
		t.Fatal("trusted UI exposed private key material")
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("CSRF cookie count=%d", len(cookies))
	}

	assertStatus(t, development.Handler(), http.MethodGet, "/requests/"+requestObject.ID+"/decision", nil, map[string]string{"X-Airlock-Dev-Identity": "reviewer@example.invalid"}, http.StatusMethodNotAllowed)
	badForm := url.Values{"csrf_token": {"wrong"}, "decision": {model.DecisionApprove}}
	badRequest := httptest.NewRequest(http.MethodPost, "/requests/"+requestObject.ID+"/decision", strings.NewReader(badForm.Encode()))
	badRequest.RemoteAddr = "127.0.0.1:1234"
	badRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badRequest.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
	badRequest.AddCookie(cookies[0])
	badResponse := httptest.NewRecorder()
	development.Handler().ServeHTTP(badResponse, badRequest)
	if badResponse.Code != http.StatusForbidden {
		t.Fatalf("bad CSRF status=%d", badResponse.Code)
	}

	form := url.Values{"csrf_token": {development.csrf}, "decision": {model.DecisionApprove}}
	approveRequest := httptest.NewRequest(http.MethodPost, "/requests/"+requestObject.ID+"/decision", strings.NewReader(form.Encode()))
	approveRequest.RemoteAddr = "127.0.0.1:1234"
	approveRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approveRequest.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
	approveRequest.AddCookie(cookies[0])
	approveResponse := httptest.NewRecorder()
	development.Handler().ServeHTTP(approveResponse, approveRequest)
	if approveResponse.Code != http.StatusSeeOther {
		t.Fatalf("approve status=%d body=%q", approveResponse.Code, approveResponse.Body.String())
	}
	record, _, found := store.Record(requestObject.ID)
	if !found || record.State != "approved" || len(record.Receipts) != 1 {
		t.Fatalf("unexpected trusted record: %#v", record)
	}
	if record.Receipts[0].Receipt.RequestDigest != requestObject.Digest || record.Receipts[0].Receipt.Reviewer != "reviewer@example.invalid" {
		t.Fatal("receipt did not bind digest and trusted identity")
	}
}

func TestTrustedStoreRejectsRequestMutationAndReplayedDecision(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	store := trustedTestStore(t, privateKey, now)
	request := trustedTestRequest(t, now)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	mutated := request
	mutated.Reason = "different display"
	if err := model.SetRequestDigest(&mutated); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(mutated); err == nil {
		t.Fatal("same request id with a new digest was accepted")
	}
	if _, err := store.Decide(request.ID, model.DecisionApprove, "reviewer@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(request.ID, model.DecisionApprove, "reviewer@example.invalid"); err == nil {
		t.Fatal("replayed approval transition accepted")
	}
}

func TestSyncerPublishesPullsAndDeliversSignedReceipt(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	requesterStateDir := t.TempDir()
	if err := os.Chmod(requesterStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	requesterStore, err := requester.NewStore(requesterStateDir, publicKey, 15*time.Minute, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// The HTTP exchange is live; keeping the request timestamps near wall time avoids
	// turning the integration assertion into a clock fixture.
	trustedStore := trustedTestStore(t, privateKey, now)
	syncer := NewSyncer(trustedStore, privateKey, trustedTestCapabilities(), "http://requester.invalid", 100*time.Millisecond, time.Hour)
	syncer.client.Transport = directTransport{handler: requester.NewServer(requesterStore).Handler()}
	syncer.now = func() time.Time { return now }
	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	record, err := requesterStore.Create(requester.CreateInput{
		CapabilityID: "github:example-owner", Action: model.ActionGitHubAddCollaborator,
		Arguments: map[string]string{"repository": "project", "permission": "push"},
		Reason:    "Enable a bounded contribution", TTLSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, _, found := trustedStore.Record(record.Request.ID); !found {
		t.Fatal("trusted node did not pull request")
	}
	if _, err := trustedStore.Decide(record.Request.ID, model.DecisionApprove, "reviewer@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	updated, found := requesterStore.Record(record.Request.ID)
	if !found || updated.State != "approved" || len(updated.Receipts) != 1 {
		t.Fatalf("requester did not accept receipt: %#v", updated)
	}
}

func TestTrustedStoreBoundsGrowthButKeepsExistingWorkActionable(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store := trustedTestStore(t, privateKey, now)
	request := trustedTestRequest(t, now)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	for index := len(store.state.Requests); index < maxTrustedRequests; index++ {
		id := fmt.Sprintf("req_fill_%020d", index)
		store.state.Requests[id] = Record{Request: model.Request{ExpiresAt: model.Timestamp(now.Add(time.Minute))}}
	}
	if err := store.Ingest(request); err != nil {
		t.Fatalf("full trusted store rejected idempotent ingest: %v", err)
	}
	additional := trustedTestRequest(t, now)
	additional.ID = "req_0123456789abcdefghim" // pragma: allowlist secret
	if err := model.SetRequestDigest(&additional); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(additional); err == nil || !strings.Contains(err.Error(), "store is full") {
		t.Fatalf("full trusted store accepted a new request: %v", err)
	}
	if _, err := store.Decide(request.ID, model.DecisionApprove, "reviewer@example.invalid"); err != nil {
		t.Fatalf("full trusted store rejected a decision for existing work: %v", err)
	}
}

func TestSyncerRefusesEnvironmentProxyRouting(t *testing.T) {
	syncer := NewSyncer(nil, nil, nil, "https://requester.example.invalid", time.Second, time.Hour)
	transport, ok := syncer.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("trusted sync transport can inherit environment proxies: %#v", syncer.client.Transport)
	}
}

func TestTrustedStoreRecoversAndPersistsInvalidLoadedReceipts(t *testing.T) {
	prepare := func(t *testing.T) (string, ed25519.PrivateKey, model.Request) {
		t.Helper()
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		store, err := NewStore(dir, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		store.now = func() time.Time { return now }
		request := trustedTestRequest(t, now)
		if err := store.Ingest(request); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Decide(request.ID, model.DecisionApprove, "reviewer@example.invalid"); err != nil {
			t.Fatal(err)
		}
		return dir, privateKey, request
	}
	assertEmptyAfterRestart := func(t *testing.T, dir string, privateKey ed25519.PrivateKey) {
		t.Helper()
		for attempt := 0; attempt < 2; attempt++ {
			store, err := NewStore(dir, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour)
			if err != nil {
				t.Fatalf("trusted restart %d failed: %v", attempt+1, err)
			}
			if len(store.state.Requests) != 0 {
				t.Fatalf("trusted restart %d retained invalid records", attempt+1)
			}
		}
	}

	t.Run("key rotation", func(t *testing.T) {
		dir, _, _ := prepare(t)
		_, rotatedKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		assertEmptyAfterRestart(t, dir, rotatedKey)
	})

	t.Run("receipt binding mismatch", func(t *testing.T) {
		dir, privateKey, request := prepare(t)
		store, err := NewStore(dir, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		next := clonePersistedState(store.state)
		record := next.Requests[request.ID]
		record.Receipts[0].Receipt.RequestID = "req_0123456789abcdefghik" // pragma: allowlist secret
		if err := model.SignReceipt(&record.Receipts[0].Receipt, privateKey); err != nil {
			t.Fatal(err)
		}
		next.Requests[request.ID] = record
		if err := store.commit(next); err != nil {
			t.Fatal(err)
		}
		assertEmptyAfterRestart(t, dir, privateKey)
	})
}

func TestTrustedStoreRetainsCurrentUndeliveredReceiptAfterRequestExpiry(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	store := trustedTestStore(t, privateKey, now)
	request := trustedTestRequest(t, now)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now.Add(9 * time.Minute) }
	receipt, err := store.Decide(request.ID, model.DecisionApprove, "reviewer@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now.Add(11 * time.Minute) }
	store.sweep()
	if _, _, found := store.Record(request.ID); !found {
		t.Fatal("expired request lost a current undelivered receipt")
	}
	if err := store.MarkDelivered(receipt.ID); err != nil {
		t.Fatal(err)
	}
	store.sweep()
	if _, _, found := store.Record(request.ID); found {
		t.Fatal("expired request with delivered receipt was not pruned")
	}
}

func TestTrustedReviewPagesAreBoundedAndStable(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	store := trustedTestStore(t, privateKey, now)
	for index, suffix := range []string{"abcdefghij", "abcdefghik", "abcdefghil"} {
		request := trustedTestRequest(t, now.Add(time.Duration(index)*time.Second))
		request.ID = "req_0123456789" + suffix
		if err := model.SetRequestDigest(&request); err != nil {
			t.Fatal(err)
		}
		if err := store.Ingest(request); err != nil {
			t.Fatal(err)
		}
	}
	first, cursor, err := store.RecordPage(2, "")
	if err != nil || len(first) != 2 || cursor == "" {
		t.Fatalf("first review page=%d cursor=%q err=%v", len(first), cursor, err)
	}
	second, next, err := store.RecordPage(2, cursor)
	if err != nil || len(second) != 1 || next != "" {
		t.Fatalf("second review page=%d next=%q err=%v", len(second), next, err)
	}
	if _, _, err := store.RecordPage(paging.MaxPage+1, ""); err == nil {
		t.Fatal("oversized trusted review page accepted")
	}
	if _, _, err := store.RecordPage(1, "req_unknown"); err == nil {
		t.Fatal("unknown trusted review cursor accepted")
	}
}

func trustedTestStore(t *testing.T, privateKey ed25519.PrivateKey, now time.Time) *Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dir, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	return store
}

type directTransport struct {
	handler http.Handler
}

func (transport directTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response := httptest.NewRecorder()
	transport.handler.ServeHTTP(response, request)
	result := response.Result()
	result.Request = request
	if result.Body == nil {
		result.Body = io.NopCloser(strings.NewReader(""))
	}
	return result, nil
}

func trustedTestCapabilities() []config.TrustedCapability {
	return []config.TrustedCapability{{
		ID: "github:example-owner", DisplayName: "Example GitHub authority",
		Adapter: model.AdapterGitHubAddCollaboratorV1, Owner: "example-owner", Collaborator: "example-agent",
		Permissions: []string{"pull", "push"},
	}}
}

func trustedTestRequest(t *testing.T, now time.Time) model.Request {
	t.Helper()
	request := model.Request{
		Version: model.RequestVersion, ID: "req_0123456789abcdefghij", CapabilityID: "github:example-owner", // pragma: allowlist secret
		Action:    model.ActionGitHubAddCollaborator,
		Arguments: map[string]string{"repository": "project", "permission": "push"},
		Reason:    "Enable a bounded contribution", CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(10 * time.Minute)),
		Nonce: "0123456789abcdefghijklmnopqrstuv",
	}
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	return request
}

func assertStatus(t *testing.T, handler http.Handler, method, target string, body *strings.Reader, headers map[string]string, want int) {
	t.Helper()
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, target, nil)
	} else {
		request = httptest.NewRequest(method, target, body)
	}
	request.RemoteAddr = "127.0.0.1:1234"
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != want {
		t.Fatalf("%s %s status=%d want=%d body=%q", method, target, response.Code, want, response.Body.String())
	}
}
