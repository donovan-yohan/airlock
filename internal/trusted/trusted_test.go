package trusted

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/donovan-yohan/airlock/internal/config"
	"github.com/donovan-yohan/airlock/internal/model"
	"github.com/donovan-yohan/airlock/internal/requester"
	"github.com/donovan-yohan/airlock/internal/statefile"
)

func TestExecutionPlanIsTypedAbsoluteAndHasFixedEnvironment(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	plan, err := validateAndPlan(trustedTestRequest(t, now), trustedTestCapabilities(), now, 15*time.Minute, "/opt/airlock/bin/gh")
	if err != nil {
		t.Fatal(err)
	}
	wantArgv := []string{"api", "--method", "PUT", "repos/example-owner/project/collaborators/example-agent", "-f", "permission=push", "--silent"}
	if plan.Executable != "/opt/airlock/bin/gh" || !equalStrings(plan.Argv, wantArgv) || plan.Display != "/opt/airlock/bin/gh api --method PUT repos/example-owner/project/collaborators/example-agent -f permission=push --silent" {
		t.Fatalf("unexpected direct-exec plan: %#v", plan)
	}
	environment := minimalChildEnvironment("/var/lib/airlock/gh")
	for _, forbidden := range []string{"GH_TOKEN=", "GITHUB_TOKEN=", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY="} {
		for _, value := range environment {
			if strings.HasPrefix(value, forbidden) {
				t.Fatalf("child environment leaked %s", forbidden)
			}
		}
	}
	if !contains(environment, "GH_CONFIG_DIR=/var/lib/airlock/gh") || !contains(environment, "GH_PROMPT_DISABLED=1") || !contains(environment, "NO_COLOR=1") || !contains(environment, "HOME=/var/lib/airlock/gh") {
		t.Fatalf("child environment is not the fixed minimum: %#v", environment)
	}
	for _, hostile := range []model.Request{
		mutatedRequest(t, now, map[string]string{"repository": "project;id", "permission": "push"}),
		mutatedRequest(t, now, map[string]string{"repository": "project", "permission": "admin"}),
	} {
		if _, err := validateAndPlan(hostile, trustedTestCapabilities(), now, 15*time.Minute, "/opt/airlock/bin/gh"); err == nil {
			t.Fatal("hostile request reached plan construction")
		}
	}
	if _, err := validateAndPlan(trustedTestRequest(t, now), trustedTestCapabilities(), now, 15*time.Minute, "gh"); err == nil {
		t.Fatal("relative executable accepted")
	}
}

func TestHostileAndStaleRequestsNeverReachExecutor(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	for _, request := range []model.Request{
		mutatedRequest(t, now, map[string]string{"repository": "project;touch", "permission": "push"}),
		mutatedRequest(t, now, map[string]string{"repository": "project", "permission": "admin"}),
		func() model.Request {
			stale := trustedTestRequest(t, now.Add(-20*time.Minute))
			return stale
		}(),
		func() model.Request {
			unknown := trustedTestRequest(t, now)
			unknown.CapabilityID = "github:unknown"
			if err := model.SetRequestDigest(&unknown); err != nil {
				t.Fatal(err)
			}
			return unknown
		}(),
	} {
		if err := store.Ingest(request); err == nil {
			t.Fatalf("hostile request was ingested: %#v", request)
		}
	}
	if runner.Calls() != 0 {
		t.Fatalf("hostile request reached executor %d times", runner.Calls())
	}
}

func TestExecuteRouteEnforcesIdentityCSRFOriginMethodFormAndQuery(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	requestObject := trustedTestRequest(t, now)
	if err := store.Ingest(requestObject); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(store, []string{"reviewer@example.invalid"}, true)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, server.Handler(), http.MethodGet, "/requests/"+requestObject.ID+"/execute", nil, map[string]string{"X-Airlock-Dev-Identity": "reviewer@example.invalid"}, http.StatusMethodNotAllowed)
	assertStatus(t, server.Handler(), http.MethodPost, "/requests/"+requestObject.ID+"/execute", strings.NewReader("csrf_token=nope"), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, http.StatusUnauthorized)

	review := trustedRequest(t, http.MethodGet, "/requests/"+requestObject.ID, nil, nil)
	review.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
	reviewResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(reviewResponse, review)
	if reviewResponse.Code != http.StatusOK || !strings.Contains(reviewResponse.Body.String(), "Approve and execute") || !strings.Contains(reviewResponse.Body.String(), "Locally reconstructed action") {
		t.Fatalf("review page was not trusted-execution UI: %d %q", reviewResponse.Code, reviewResponse.Body.String())
	}
	cookie := reviewResponse.Result().Cookies()[0]
	post := func(target, form string, headers map[string]string) *httptest.ResponseRecorder {
		r := trustedRequest(t, http.MethodPost, target, strings.NewReader(form), headers)
		r.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		return w
	}
	if got := post("/requests/"+requestObject.ID+"/execute", "csrf_token=wrong", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); got.Code != http.StatusForbidden {
		t.Fatalf("bad csrf=%d", got.Code)
	}
	if got := post("/requests/"+requestObject.ID+"/execute", url.Values{"csrf_token": {server.csrf}, "extra": {"x"}}.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); got.Code != http.StatusBadRequest {
		t.Fatalf("extra field=%d", got.Code)
	}
	if got := post("/requests/"+requestObject.ID+"/execute?x=1", url.Values{"csrf_token": {server.csrf}}.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); got.Code != http.StatusBadRequest {
		t.Fatalf("query=%d", got.Code)
	}
	if got := post("/requests/"+requestObject.ID+"/execute", url.Values{"csrf_token": {server.csrf}}.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "cross-site"}); got.Code != http.StatusForbidden {
		t.Fatalf("cross-site=%d", got.Code)
	}
	if got := post("/requests/"+requestObject.ID+"/execute", url.Values{"csrf_token": {server.csrf}}.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"}); got.Code != http.StatusSeeOther {
		t.Fatalf("execution=%d body=%q", got.Code, got.Body.String())
	}
	if runner.Calls() != 1 {
		t.Fatalf("provider calls=%d", runner.Calls())
	}
	record, _, found := store.Record(requestObject.ID)
	if !found || record.State != model.DecisionExecuted || len(record.Receipts) != 2 || record.Receipts[0].Receipt.Decision != model.DecisionApproveForExecution || record.Receipts[1].Receipt.Decision != model.DecisionExecuted {
		t.Fatalf("success did not atomically create v2 receipts: %#v", record)
	}
	terminalReview := trustedRequest(t, http.MethodGet, "/requests/"+requestObject.ID, nil, nil)
	terminalReview.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
	terminalResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(terminalResponse, terminalReview)
	terminalBody := terminalResponse.Body.String()
	if terminalResponse.Code != http.StatusOK || !strings.Contains(terminalBody, "this does not prove GitHub state") || !strings.Contains(terminalBody, "independent read-only provider check") || strings.Contains(terminalBody, "Approve and execute") {
		t.Fatalf("executed review page overclaimed provider state: %d %q", terminalResponse.Code, terminalBody)
	}
}

func TestApprovalReservationPrecedesExactlyOneConcurrentInvocation(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	request := trustedTestRequest(t, now)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	runner.release = release
	runner.onRun = func() {
		record, _, found := store.Record(request.ID)
		if !found || record.State != attemptStatusRunning || len(record.Receipts) != 1 || len(record.Attempts) != 1 || record.Receipts[0].Receipt.Decision != model.DecisionApproveForExecution {
			t.Errorf("effect began without durable reservation: %#v", record)
		}
	}
	done := make(chan error, 1)
	go func() { done <- store.Execute(context.Background(), request.ID, "reviewer@example.invalid") }()
	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("provider did not begin")
	}
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid"); !errors.Is(err, ErrExecutionActive) {
		t.Fatalf("concurrent execute=%v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if runner.Calls() != 1 {
		t.Fatalf("provider invocation count=%d", runner.Calls())
	}
}

func TestAmbiguousExecutionFailureIsUncertainRetryableAndDoesNotPersistOutput(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	request := trustedTestRequest(t, now)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	canary := "provider-output-canary-DO-NOT-PERSIST"
	runner.err = errors.New(canary)
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid"); !errors.Is(err, ErrExecutionUncertain) {
		t.Fatalf("failure result=%v", err)
	}
	record, _, _ := store.Record(request.ID)
	if record.State != attemptStatusUncertain || len(record.Receipts) != 1 || len(record.Attempts) != 1 || record.Attempts[0].FailureCode != "nonzero_exit" {
		t.Fatalf("ambiguous attempt unsafe state: %#v", record)
	}
	encoded, err := json.Marshal(store.state)
	if err != nil || strings.Contains(string(encoded), canary) {
		t.Fatal("raw executor output/error leaked to state")
	}
	runner.err = nil
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid"); err != nil {
		t.Fatalf("explicit retry=%v", err)
	}
	record, _, _ = store.Record(request.ID)
	if record.State != model.DecisionExecuted || len(record.Attempts) != 2 || len(record.Receipts) != 3 {
		t.Fatalf("retry did not preserve bounded history: %#v", record)
	}
}

func TestMissingExecutableCancelAndRestartAreTruthful(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, _ := trustedTestStore(t, privateKey, now)
	store.runner = directExecutionRunner{}
	store.execution.GitHubCLIPath = "/definitely/not/a/gh-binary"
	request := trustedTestRequest(t, now)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid"); !errors.Is(err, ErrExecutionFailed) {
		t.Fatalf("missing executable=%v", err)
	}
	record, _, _ := store.Record(request.ID)
	if record.State != attemptStatusFailed || record.Attempts[0].FailureCode != "missing_executable" || len(record.Receipts) != 1 {
		t.Fatalf("missing executable became success: %#v", record)
	}

	// A crash after reservation leaves durable running state. Construction must
	// mark it interrupted and never execute it automatically.
	second := trustedTestRequest(t, now)
	second.ID = "req_0123456789abcdefghik" // pragma: allowlist secret
	if err := model.SetRequestDigest(&second); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(second); err != nil {
		t.Fatal(err)
	}
	store.execution.GitHubCLIPath = "/trusted/fake/gh"
	if _, _, _, err := store.reserveExecution(second.ID, "reviewer@example.invalid"); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewStore(filepathDir(store.path), privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, *store.execution)
	if err != nil {
		t.Fatal(err)
	}
	record, _, _ = restarted.Record(second.ID)
	if record.State != attemptStatusUncertain || record.Attempts[0].Status != attemptStatusUncertain || record.Attempts[0].FailureCode != "interrupted" {
		t.Fatalf("running attempt did not become uncertain: %#v", record)
	}
}

func TestCancellationAndCompletionPersistenceNeverClaimExecuted(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	request := trustedTestRequest(t, now)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	runner.release = make(chan struct{})
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Execute(cancelled, request.ID, "reviewer@example.invalid"); !errors.Is(err, ErrExecutionUncertain) {
		t.Fatalf("cancelled execute=%v", err)
	}
	record, _, _ := store.Record(request.ID)
	if record.State != attemptStatusUncertain || record.Attempts[0].FailureCode != "cancelled" || len(record.Receipts) != 1 {
		t.Fatalf("cancellation claimed execution: %#v", record)
	}

	// A direct child can return zero while the terminal atomic write fails. The
	// fallback must be uncertain, never executed, and must contain no output.
	second := trustedTestRequest(t, now)
	second.ID = "req_0123456789abcdefghil" // pragma: allowlist secret
	if err := model.SetRequestDigest(&second); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(second); err != nil {
		t.Fatal(err)
	}
	runner.release = nil
	writes := 0
	store.save = func(path string, value any) error {
		writes++
		if writes == 2 { // reservation is write 1; completion is write 2
			return errors.New("synthetic completion persistence failure")
		}
		return statefile.Save(path, value)
	}
	if err := store.Execute(context.Background(), second.ID, "reviewer@example.invalid"); !errors.Is(err, ErrExecutionUncertain) {
		t.Fatalf("completion persistence result=%v", err)
	}
	record, _, _ = store.Record(second.ID)
	if record.State != attemptStatusUncertain || record.Attempts[0].FailureCode != "completion_persistence_failed" || len(record.Receipts) != 1 {
		t.Fatalf("completion persistence claimed success: %#v", record)
	}

	// Save can rename the executed state and then report a parent-directory
	// fsync failure. That unacknowledged file must be overwritten by the same
	// conservative uncertain fallback rather than reloaded and published.
	third := trustedTestRequest(t, now)
	third.ID = "req_0123456789abcdefghim" // pragma: allowlist secret
	if err := model.SetRequestDigest(&third); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(third); err != nil {
		t.Fatal(err)
	}
	writes = 0
	store.save = func(path string, value any) error {
		writes++
		if err := statefile.Save(path, value); err != nil {
			return err
		}
		if writes == 2 { // the completed file exists, but durability was not confirmed
			return errors.New("synthetic post-rename directory sync failure")
		}
		return nil
	}
	if err := store.Execute(context.Background(), third.ID, "reviewer@example.invalid"); !errors.Is(err, ErrExecutionUncertain) {
		t.Fatalf("post-rename completion result=%v", err)
	}
	record, _, _ = store.Record(third.ID)
	if record.State != attemptStatusUncertain || record.Attempts[0].FailureCode != "completion_persistence_failed" || len(record.Receipts) != 1 {
		t.Fatalf("post-rename failure exposed executed state: %#v", record)
	}
	var durable persistedState
	if err := statefile.Load(store.path, &durable); err != nil {
		t.Fatal(err)
	}
	durableRecord := durable.Requests[third.ID]
	if durableRecord.State != attemptStatusUncertain || len(durableRecord.Receipts) != 1 {
		t.Fatalf("post-rename fallback was not durable: %#v", durableRecord)
	}
}

func TestActionServiceOwnsExecutionAfterFrontendDisconnect(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	request := trustedTestRequest(t, now)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	service := NewActionService(store)
	release := make(chan struct{})
	runner.release = release
	frontend, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Execute(frontend, request.ID, "reviewer@example.invalid") }()
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("daemon-owned execution did not start")
	}
	cancel()
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("frontend disconnect cancelled daemon execution: %v", err)
	}
	if runner.Calls() != 1 {
		t.Fatalf("provider calls=%d want 1", runner.Calls())
	}
	record, _, found := store.Record(request.ID)
	if !found || record.State != model.DecisionExecuted || len(record.Attempts) != 1 {
		t.Fatalf("daemon-owned execution did not complete exactly once: %#v", record)
	}
}

func TestActionServiceShutdownCancelsAndPersistsInFlightExecution(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	request := trustedTestRequest(t, now)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	service := NewActionService(store)
	runner.release = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- service.Execute(context.Background(), request.ID, "reviewer@example.invalid") }()
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("in-flight execution did not start")
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Shutdown(shutdownContext); err != nil {
		t.Fatalf("shutdown=%v", err)
	}
	if err := <-done; !errors.Is(err, ErrExecutionUncertain) {
		t.Fatalf("cancelled execution=%v", err)
	}
	record, _, found := store.Record(request.ID)
	if !found || record.State != attemptStatusUncertain || len(record.Attempts) != 1 || record.Attempts[0].FailureCode != "cancelled" {
		t.Fatalf("shutdown did not persist cancelled uncertainty: %#v", record)
	}
	if err := service.Execute(context.Background(), request.ID, "reviewer@example.invalid"); !errors.Is(err, ErrExecutionUnavailable) {
		t.Fatalf("execute after shutdown=%v", err)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatalf("idempotent shutdown=%v", err)
	}
}

func TestActionServiceShutdownRespectsDeadline(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	request := trustedTestRequest(t, now)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	service := NewActionService(store)
	release := make(chan struct{})
	runner.release = release
	runner.ignoreCancellation = true
	done := make(chan error, 1)
	go func() { done <- service.Execute(context.Background(), request.ID, "reviewer@example.invalid") }()
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("in-flight execution did not start")
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := service.Shutdown(shutdownContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded shutdown=%v", err)
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrExecutionUncertain) {
		t.Fatalf("uncooperative runner completion=%v", err)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown after completion=%v", err)
	}
}

func TestGitHubConfigDirectoryMustBePrivateAndReal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission assertions")
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newStore := func(configDir string) error {
		stateDir := t.TempDir()
		if err := os.Chmod(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := NewStore(stateDir, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, ExecutionConfig{GitHubCLIPath: "/trusted/fake/gh", GitHubConfigDir: configDir, Timeout: time.Minute})
		return err
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "missing")
	if err := newStore(missing); err != nil {
		t.Fatalf("missing private directory was not created: %v", err)
	}
	if info, err := os.Lstat(missing); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("created GitHub config directory mode=%v err=%v", info.Mode(), err)
	}

	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("not a config directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newStore(regular); err == nil {
		t.Fatal("regular GitHub config path was accepted")
	}

	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "symlink")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if err := newStore(symlink); err == nil {
		t.Fatal("symlink GitHub config directory was accepted")
	}

	permissive := filepath.Join(root, "permissive")
	if err := os.Mkdir(permissive, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(permissive, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := newStore(permissive); err == nil {
		t.Fatal("group-accessible GitHub config directory was accepted")
	}
}

func TestV2ReceiptsSyncAndLegacyV1RecoveryRemainVisible(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	requesterDir := t.TempDir()
	if err := os.Chmod(requesterDir, 0o700); err != nil {
		t.Fatal(err)
	}
	requesterStore, err := requester.NewStore(requesterDir, publicKey, 15*time.Minute, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	trustedStore, _ := trustedTestStore(t, privateKey, now)
	syncer := NewSyncer(trustedStore, privateKey, trustedTestCapabilities(), "http://requester.invalid", time.Second, time.Hour)
	syncer.client.Transport = directTransport{handler: requester.NewServer(requesterStore).Handler()}
	syncer.now = func() time.Time { return now }
	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	record, err := requesterStore.Create(requester.CreateInput{CapabilityID: "github:example-owner", Action: model.ActionGitHubAddCollaborator, Arguments: map[string]string{"repository": "project", "permission": "push"}, Reason: "Enable bounded contribution", TTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := trustedStore.Execute(context.Background(), record.Request.ID, "reviewer@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	updated, found := requesterStore.Record(record.Request.ID)
	if !found || updated.State != model.DecisionExecuted || len(updated.Receipts) != 2 {
		t.Fatalf("requester did not accept v2 receipt pair: %#v", updated)
	}

	legacyDir := t.TempDir()
	if err := os.Chmod(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy, err := NewStore(legacyDir, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	legacy.now = func() time.Time { return now }
	legacyRequest := trustedTestRequest(t, now)
	approval := legacyReceipt(t, privateKey, legacyRequest, model.DecisionApproveForManualExecution, now, "rec_0123456789abcdefghij")
	manual := legacyReceipt(t, privateKey, legacyRequest, model.DecisionManuallyExecuted, now.Add(time.Second), "rec_0123456789abcdefghik")
	legacy.state.Requests[legacyRequest.ID] = Record{Request: legacyRequest, State: "manually_executed", Receipts: []Delivery{{Receipt: approval}, {Receipt: manual}}}
	if err := legacy.commit(legacy.state); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewStore(legacyDir, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	legacyRecord, _, found := recovered.Record(legacyRequest.ID)
	if !found || legacyRecord.State != "manually_executed" || len(legacyRecord.Receipts) != 2 {
		t.Fatalf("legacy v1 receipt recovery failed: %#v", legacyRecord)
	}
}

type recordingRunner struct {
	mu                 sync.Mutex
	calls              int
	plan               ExecutionPlan
	env                []string
	err                error
	started            chan struct{}
	release            <-chan struct{}
	onRun              func()
	ignoreCancellation bool
}

func (r *recordingRunner) Run(ctx context.Context, plan ExecutionPlan, environment []string) error {
	r.mu.Lock()
	r.calls++
	r.plan = plan
	r.env = append([]string(nil), environment...)
	started := r.started
	release := r.release
	err := r.err
	onRun := r.onRun
	ignoreCancellation := r.ignoreCancellation
	r.mu.Unlock()
	select {
	case started <- struct{}{}:
	default:
	}
	if onRun != nil {
		onRun()
	}
	if release != nil {
		if ignoreCancellation {
			<-release
			return err
		}
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (r *recordingRunner) Calls() int { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }

func trustedTestStore(t *testing.T, privateKey ed25519.PrivateKey, now time.Time) (*Store, *recordingRunner) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(dir, "gh-config")
	store, err := NewStore(dir, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, ExecutionConfig{GitHubCLIPath: "/trusted/fake/gh", GitHubConfigDir: configDir, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	runner := &recordingRunner{started: make(chan struct{}, 2)}
	store.runner = runner
	return store, runner
}

type directTransport struct{ handler http.Handler }

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
	return []config.TrustedCapability{{ID: "github:example-owner", DisplayName: "Example GitHub authority", Adapter: model.AdapterGitHubAddCollaboratorV1, Owner: "example-owner", Collaborator: "example-agent", Permissions: []string{"pull", "push"}}}
}

func trustedTestRequest(t *testing.T, now time.Time) model.Request {
	t.Helper()
	request := model.Request{Version: model.RequestVersion, ID: "req_0123456789abcdefghij", CapabilityID: "github:example-owner", Action: model.ActionGitHubAddCollaborator, Arguments: map[string]string{"repository": "project", "permission": "push"}, Reason: "Enable a bounded contribution", CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(10 * time.Minute)), Nonce: "0123456789abcdefghijklmnopqrstuv"}
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	return request
}

func mutatedRequest(t *testing.T, now time.Time, arguments map[string]string) model.Request {
	t.Helper()
	request := trustedTestRequest(t, now)
	request.Arguments = arguments
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	return request
}

func legacyReceipt(t *testing.T, privateKey ed25519.PrivateKey, request model.Request, decision string, now time.Time, id string) model.Receipt {
	t.Helper()
	receipt := model.Receipt{Version: model.ReceiptVersionV1, ID: id, RequestID: request.ID, RequestDigest: request.Digest, Decision: decision, Reviewer: "reviewer@example.invalid", AdapterVersion: model.AdapterGitHubAddCollaboratorV1, CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(time.Hour))}
	if err := model.SignReceipt(&receipt, privateKey); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func trustedRequest(t *testing.T, method, target string, body io.Reader, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, target, body)
	r.RemoteAddr = "127.0.0.1:1234"
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	return r
}

func assertStatus(t *testing.T, handler http.Handler, method, target string, body io.Reader, headers map[string]string, want int) {
	t.Helper()
	r := trustedRequest(t, method, target, body, headers)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s %s status=%d want=%d body=%q", method, target, w.Code, want, w.Body.String())
	}
}

func equalStrings(a, b []string) bool {
	return len(a) == len(b) && func() bool {
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}()
}
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
