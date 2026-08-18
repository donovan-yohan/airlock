package trusted

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	"github.com/donovan-yohan/airlock/internal/mcp"
	"github.com/donovan-yohan/airlock/internal/model"
	"github.com/donovan-yohan/airlock/internal/paging"
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
	if plan.Executable != "/opt/airlock/bin/gh" || !equalStrings(plan.Argv, wantArgv) || escapedCommand(plan) != `"/opt/airlock/bin/gh" "api" "--method" "PUT" "repos/example-owner/project/collaborators/example-agent" "-f" "permission=push" "--silent"` || plan.Digest == "" {
		t.Fatalf("unexpected direct-exec plan: %#v", plan)
	}
	environment := minimalChildEnvironment()
	for _, forbidden := range []string{"GH_TOKEN=", "GITHUB_TOKEN=", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY="} {
		for _, value := range environment {
			if strings.HasPrefix(value, forbidden) {
				t.Fatalf("child environment leaked %s", forbidden)
			}
		}
	}
	if !contains(environment, "GH_CONFIG_DIR=/airlock/home/.config/gh") || !contains(environment, "GH_PROMPT_DISABLED=1") || !contains(environment, "NO_COLOR=1") || !contains(environment, "HOME=/airlock/home") || !contains(environment, "XDG_CONFIG_HOME=/airlock/home/.config") {
		t.Fatalf("child environment is not the fixed minimum: %#v", environment)
	}
	if wantPolicy := append(append([]string(nil), environment...), "PWD=/airlock/work"); !equalStrings(plan.EnvironmentPolicy, wantPolicy) {
		t.Fatalf("reviewed environment policy diverged from runtime: plan=%#v runtime=%#v", plan.EnvironmentPolicy, wantPolicy)
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
	now := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Second)
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
	if reviewResponse.Code != http.StatusOK || !strings.Contains(reviewResponse.Body.String(), "Approve exact plan and execute") || !strings.Contains(reviewResponse.Body.String(), "Resolved immutable plan") {
		t.Fatalf("review page was not trusted-execution UI: %d %q", reviewResponse.Code, reviewResponse.Body.String())
	}
	cookie := reviewResponse.Result().Cookies()[0]
	planDigest := trustedPlanDigest(t, store, requestObject.ID)
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
	if got := post("/requests/"+requestObject.ID+"/execute", url.Values{"csrf_token": {server.csrf}, "plan_digest": {planDigest}}.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "cross-site"}); got.Code != http.StatusForbidden {
		t.Fatalf("cross-site=%d", got.Code)
	}
	if got := post("/requests/"+requestObject.ID+"/execute", url.Values{"csrf_token": {server.csrf}, "plan_digest": {planDigest}, "confirm_full_authority": {"true"}}.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"}); got.Code != http.StatusSeeOther {
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
	if terminalResponse.Code != http.StatusOK || !strings.Contains(terminalBody, "this does not prove GitHub state") || !strings.Contains(terminalBody, "independent read-only provider check") || strings.Contains(terminalBody, "Approve exact plan and execute") {
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
	planDigest := trustedPlanDigest(t, store, request.ID)
	go func() {
		done <- store.Execute(context.Background(), request.ID, "reviewer@example.invalid", planDigest)
	}()
	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("provider did not begin")
	}
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", planDigest); !errors.Is(err, ErrExecutionActive) {
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
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID)); !errors.Is(err, ErrExecutionUncertain) {
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
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID)); err != nil {
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
	store.verifyExecutable = true
	store.execution.GitHubCLIPath = "/definitely/not/a/gh-binary"
	request := trustedTestRequest(t, now)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID)); !errors.Is(err, ErrExecutionFailed) {
		t.Fatalf("missing executable=%v", err)
	}
	record, _, _ := store.Record(request.ID)
	if record.State != "pending" || len(record.Attempts) != 0 || len(record.Receipts) != 0 {
		t.Fatalf("missing executable reserved execution: %#v", record)
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
	if _, _, _, err := store.reserveExecution(second.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, second.ID)); err != nil {
		t.Fatal(err)
	}
	beforeRecovery := trustedStateBytes(t, store.path)
	restarted, err := NewStore(filepathDir(store.path), privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, *store.execution)
	if err != nil {
		t.Fatal(err)
	}
	record, _, _ = restarted.Record(second.ID)
	if record.State != attemptStatusUncertain || record.Attempts[0].Status != attemptStatusUncertain || record.Attempts[0].FailureCode != "interrupted" {
		t.Fatalf("running attempt did not become uncertain: %#v", record)
	}
	if afterRecovery := trustedStateBytes(t, store.path); bytes.Equal(beforeRecovery, afterRecovery) {
		t.Fatal("running recovery did not durably publish uncertain state")
	}
}

func TestServingStoreStartupPreservesDurableEvidenceAcrossEnvironmentAndPolicyChanges(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("missing or non-private hosts fail before state rewrite", func(t *testing.T) {
		for _, change := range []struct {
			name  string
			apply func(t *testing.T, path string)
		}{
			{"missing", func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}},
			{"non-private", func(t *testing.T, path string) {
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			}},
		} {
			t.Run(change.name, func(t *testing.T) {
				store, _ := trustedTestStore(t, privateKey, now)
				request := currentCommandRequest(t, now, "req_0123456789abcdefghij", []string{"api", "user"})
				if err := store.Ingest(request); err != nil {
					t.Fatal(err)
				}
				before := trustedStateBytes(t, store.path)
				change.apply(t, filepath.Join(store.execution.GitHubConfigDir, "hosts.yml"))
				if _, err := NewStore(filepath.Dir(store.path), privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, trustedTestExecutionConfig(store.execution.GitHubConfigDir)); err == nil {
					t.Fatal("invalid hosts.yml allowed a serving store startup")
				}
				if after := trustedStateBytes(t, store.path); !bytes.Equal(before, after) {
					t.Fatal("invalid hosts.yml rewrote trusted durable state")
				}
			})
		}
	})

	t.Run("TTL tightening preserves request and receipt history", func(t *testing.T) {
		store, _ := trustedTestStore(t, privateKey, now)
		request := currentCommandRequest(t, now, "req_0123456789abcdefghij", []string{"api", "user"})
		if err := store.Ingest(request); err != nil {
			t.Fatal(err)
		}
		if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID)); err != nil {
			t.Fatal(err)
		}
		for _, delivery := range store.state.Requests[request.ID].Receipts {
			if err := store.MarkDelivered(delivery.Receipt.ID); err != nil {
				t.Fatal(err)
			}
		}
		before := trustedStateBytes(t, store.path)
		recovered, err := NewStore(filepath.Dir(store.path), privateKey, trustedTestCapabilities(), 5*time.Minute, time.Minute, *store.execution)
		if err != nil {
			t.Fatal(err)
		}
		if record, _, found := recovered.Record(request.ID); !found || record.State != model.DecisionExecuted || len(record.Receipts) != 2 {
			t.Fatalf("TTL tightening erased valid durable request or receipt: found=%v record=%#v", found, record)
		}
		if after := trustedStateBytes(t, store.path); !bytes.Equal(before, after) {
			t.Fatal("TTL tightening rewrote trusted request/receipt history")
		}
	})

	t.Run("removed legacy capability preserves non-actionable history", func(t *testing.T) {
		store, _ := trustedTestStore(t, privateKey, now)
		request := trustedTestRequest(t, now)
		if err := store.Ingest(request); err != nil {
			t.Fatal(err)
		}
		before := trustedStateBytes(t, store.path)
		recovered, err := NewStore(filepath.Dir(store.path), privateKey, nil, 15*time.Minute, time.Hour, *store.execution)
		if err != nil {
			t.Fatal(err)
		}
		if record, plan, found := recovered.Record(request.ID); !found || record.State != "pending" || plan != nil {
			t.Fatalf("removed capability history was not retained/non-actionable: found=%v state=%q plan=%#v", found, record.State, plan)
		}
		if after := trustedStateBytes(t, store.path); !bytes.Equal(before, after) {
			t.Fatal("removed capability rewrote trusted history")
		}
	})

	t.Run("bad receipt signature preserves bytes and refuses startup", func(t *testing.T) {
		store, _ := trustedTestStore(t, privateKey, now)
		request := currentCommandRequest(t, now, "req_0123456789abcdefghij", []string{"api", "user"})
		if err := store.Ingest(request); err != nil {
			t.Fatal(err)
		}
		if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID)); err != nil {
			t.Fatal(err)
		}
		tampered := clonePersistedState(store.state)
		record := tampered.Requests[request.ID]
		record.Receipts[0].Receipt.Signature = strings.Repeat("A", len(record.Receipts[0].Receipt.Signature))
		tampered.Requests[request.ID] = record
		if err := store.commit(tampered); err != nil {
			t.Fatal(err)
		}
		before := trustedStateBytes(t, store.path)
		if _, err := NewStore(filepath.Dir(store.path), privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, *store.execution); err == nil {
			t.Fatal("tampered signature was silently removed during startup")
		}
		if after := trustedStateBytes(t, store.path); !bytes.Equal(before, after) {
			t.Fatal("tampered trusted record was rewritten")
		}
	})

	t.Run("attempt history exposes its persisted plan without current re-resolution", func(t *testing.T) {
		store, _ := trustedTestStore(t, privateKey, now)
		request := currentCommandRequest(t, now, "req_0123456789abcdefghij", []string{"api", "user"})
		if err := store.Ingest(request); err != nil {
			t.Fatal(err)
		}
		if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID)); err != nil {
			t.Fatal(err)
		}
		want := store.state.Requests[request.ID].Attempts[0].Plan.Digest
		changed := *store.execution
		changed.ProfileConfigVersion = "changed-policy-v2"
		recovered, err := NewStore(filepath.Dir(store.path), privateKey, nil, 15*time.Minute, time.Hour, changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, plan, found := recovered.Record(request.ID); !found || plan == nil || plan.Digest != want {
			t.Fatalf("completed immutable plan was re-resolved or hidden: found=%v plan=%#v", found, plan)
		}
	})
}

func trustedStateBytes(t *testing.T, path string) []byte {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

func TestMaximumTrustedStateFitsAtomicFileWithLiteralEscapableData(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, _ := trustedTestStore(t, privateKey, now)
	store.execution.GitHubCLIPath = "/" + strings.Repeat(`"`, maxExecutionPathBytes-1)
	store.execution.Profile = model.CommandProfile{
		ID: model.ProfileGitHubCommandID, Version: model.ProfileGitHubCommandVersion,
		DisplayName: strings.Repeat(`"`, 200), AuthorityLabel: strings.Repeat(`"`, 200), SandboxLabel: strings.Repeat(`"`, 200),
		NetworkLabel: strings.Repeat(`"`, 200), CWDLabel: strings.Repeat(`"`, 200), OutputLabel: strings.Repeat(`"`, 200),
		Limits: model.ProfileLimits{MaxArgvCount: model.MaxArgvCount, MaxArgumentBytes: model.MaxArgumentBytes, MaxAggregateBytes: model.MaxArgvAggregateBytes},
	}
	store.execution.ExecutionIdentity = strings.Repeat(`"`, 200)
	store.execution.ProfileConfigVersion = strings.Repeat("p", 64)

	state := persistedState{Requests: make(map[string]Record, maxTrustedRequests)}
	for index := range maxTrustedRequests {
		request := maximalTrustedRequest(t, now, fmt.Sprintf("req_%020d", index))
		plan, err := resolveExecutionPlan(request, store.capabilities, now, store.requestMaxTTL, store.execution)
		if err != nil {
			t.Fatal(err)
		}
		record := Record{Request: request, State: model.DecisionExecuted, Receipts: make([]Delivery, 0, maxReceiptsPerRecord), Attempts: make([]ExecutionAttempt, 0, maxExecutionAttempts)}
		for attemptIndex := range maxExecutionAttempts {
			at := now.Add(time.Duration(attemptIndex) * time.Second)
			approval, err := store.newReceipt(request, model.DecisionApproveForExecution, strings.Repeat(`"`, 254), plan, at)
			if err != nil {
				t.Fatal(err)
			}
			record.Receipts = append(record.Receipts, Delivery{Receipt: approval})
			status, code := attemptStatusUncertain, "nonzero_exit"
			if attemptIndex == maxExecutionAttempts-1 {
				status, code = attemptStatusSucceeded, ""
			}
			record.Attempts = append(record.Attempts, ExecutionAttempt{
				ID: fmt.Sprintf("att_%020d_%020d", index, attemptIndex), RequestDigest: request.Digest, Reviewer: strings.Repeat(`"`, 254),
				ProfileID: plan.ProfileID, ProfileVersion: plan.ProfileVersion, PlanDigest: plan.Digest, Plan: cloneExecutionPlan(&plan),
				Status: status, StartedAt: model.Timestamp(at), FinishedAt: model.Timestamp(at), FailureCode: code,
				OutputPreview: &ExecutionOutputPreview{Stdout: strings.Repeat(`"`, maxExecutionOutputPreviewBytes), Stderr: strings.Repeat(`\`, maxExecutionOutputPreviewBytes)},
			})
		}
		executed, err := store.newReceipt(request, model.DecisionExecuted, strings.Repeat(`"`, 254), plan, now.Add(time.Duration(maxExecutionAttempts)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		record.Receipts = append(record.Receipts, Delivery{Receipt: executed})
		state.Requests[request.ID] = record
	}
	if err := store.commit(state); err != nil {
		t.Fatalf("maximum trusted state exceeded the atomic state-file ceiling: %v", err)
	}
	raw := trustedStateBytes(t, store.path)
	if len(raw) > 14<<20 || !bytes.Contains(raw, []byte(`\"`)) || !bytes.Contains(raw, []byte(`\\`)) {
		t.Fatalf("maximum trusted state lacked worst-case JSON escaping headroom: bytes=%d", len(raw))
	}
	t.Logf("maximum trusted worst-case escaped state bytes=%d", len(raw))
	if err := store.Ingest(maximalTrustedRequest(t, now, "req_0123456789abcdefghij")); err == nil || !strings.Contains(err.Error(), "store is full") {
		t.Fatalf("trusted count cap did not bind before state-file bytes: %v", err)
	}
	restarted, err := NewStore(filepath.Dir(store.path), privateKey, trustedTestCapabilities(), store.requestMaxTTL, store.receiptTTL, *store.execution)
	if err != nil {
		t.Fatalf("maximum trusted state did not restart: %v", err)
	}
	if len(restarted.state.Requests) != maxTrustedRequests {
		t.Fatalf("maximum trusted state restart count=%d want=%d", len(restarted.state.Requests), maxTrustedRequests)
	}
}

func maximalTrustedRequest(t *testing.T, now time.Time, id string) model.Request {
	t.Helper()
	request := currentCommandRequest(t, now, id, maximalControlArgv())
	request.Reason = strings.Repeat(`"`, model.MaxReasonBytes)
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	return request
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
	if err := store.Execute(cancelled, request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID)); !errors.Is(err, ErrExecutionUncertain) {
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
	if err := store.Execute(context.Background(), second.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, second.ID)); !errors.Is(err, ErrExecutionUncertain) {
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
	if err := store.Execute(context.Background(), third.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, third.ID)); !errors.Is(err, ErrExecutionUncertain) {
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

func TestExecutionClockRollbackWritesReloadableMonotonicState(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, startedAt)
	request := trustedTestRequest(t, startedAt)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}

	var clockMu sync.RWMutex
	current := startedAt
	store.now = func() time.Time {
		clockMu.RLock()
		defer clockMu.RUnlock()
		return current
	}
	release := make(chan struct{})
	runner.release = release
	done := make(chan error, 1)
	go func() {
		done <- store.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID))
	}()
	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("provider did not begin")
	}
	clockMu.Lock()
	current = startedAt.Add(-90 * time.Second)
	clockMu.Unlock()
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("execution after backwards clock step: %v", err)
	}

	record, _, found := store.Record(request.ID)
	if !found || record.State != model.DecisionExecuted || len(record.Attempts) != 1 || len(record.Receipts) != 2 {
		t.Fatalf("terminal record after clock step: found=%v record=%#v", found, record)
	}
	attemptStarted, _ := time.Parse(time.RFC3339, record.Attempts[0].StartedAt)
	attemptFinished, _ := time.Parse(time.RFC3339, record.Attempts[0].FinishedAt)
	approvalCreated, _ := time.Parse(time.RFC3339, record.Receipts[0].Receipt.CreatedAt)
	executedCreated, _ := time.Parse(time.RFC3339, record.Receipts[1].Receipt.CreatedAt)
	if attemptFinished.Before(attemptStarted) || executedCreated.Before(approvalCreated) || !attemptFinished.Equal(executedCreated) {
		t.Fatalf("clock rollback inverted durable events: attempt=%s..%s receipts=%s..%s", attemptStarted, attemptFinished, approvalCreated, executedCreated)
	}
	if _, err := NewStore(filepath.Dir(store.path), privateKey, trustedTestCapabilities(), store.requestMaxTTL, store.receiptTTL, *store.execution); err != nil {
		t.Fatalf("trusted store refused its own clock-rollback state: %v", err)
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
	go func() {
		done <- service.Execute(frontend, request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID), true)
	}()
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

func TestActionServiceRequiresExplicitFullAuthorityConfirmation(t *testing.T) {
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
	digest := trustedPlanDigest(t, store, request.ID)
	if err := service.Execute(context.Background(), request.ID, "reviewer@example.invalid", digest, false); !errors.Is(err, ErrExecutionConfirmationRequired) {
		t.Fatalf("missing confirmation error=%v", err)
	}
	if runner.Calls() != 0 {
		t.Fatal("unconfirmed action reached provider")
	}
	record, _, found := service.Record(request.ID)
	if !found || record.State != "pending" || len(record.Attempts) != 0 || len(record.Receipts) != 0 {
		t.Fatalf("unconfirmed action mutated durable state: %#v", record)
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
	go func() {
		done <- service.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID), true)
	}()
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
	if err := service.Execute(context.Background(), request.ID, "reviewer@example.invalid", strings.Repeat("a", 64), true); !errors.Is(err, ErrExecutionUnavailable) {
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
	go func() {
		done <- service.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID), true)
	}()
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
		_, err := NewStore(stateDir, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, trustedTestExecutionConfig(configDir))
		return err
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "missing")
	if err := newStore(missing); err == nil {
		t.Fatal("missing GitHub config directory was accepted without a private hosts.yml")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("startup created an unauthenticated GitHub config directory: %v", err)
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

func TestSyncerPagesPendingBacklogWithoutWholeResponseFailure(t *testing.T) {
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
	for index := 0; index < maxPullPageRecords+3; index++ {
		if _, err := requesterStore.Create(requester.CreateInput{
			ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion,
			Argv: []string{"api", fmt.Sprintf("repos/example-owner/project-%02d", index)}, Reason: "paged pending backlog", TTLSeconds: 600,
		}); err != nil {
			t.Fatalf("create backlog request %d: %v", index, err)
		}
	}
	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatalf("first pending page: %v", err)
	}
	if got := len(trustedStore.state.Requests); got != maxPullPageRecords || syncer.pullCursor == "" {
		t.Fatalf("first pending page count=%d cursor=%q", got, syncer.pullCursor)
	}
	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatalf("second pending page: %v", err)
	}
	if got := len(trustedStore.state.Requests); got != maxPullPageRecords+3 || syncer.pullCursor != "" {
		t.Fatalf("completed pending pagination count=%d cursor=%q", got, syncer.pullCursor)
	}
}

func TestSyncerAdvancesPastEnvelopeRejectedRecord(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, _ := trustedTestStore(t, privateKey, now)
	requests := pendingSyncRequests(t, now, maxPullPageRecords)
	requests[0].ExpiresAt = model.Timestamp(now.Add(30 * time.Minute))
	if err := model.SetRequestDigest(&requests[0]); err != nil {
		t.Fatal(err)
	}
	nextCursor, err := paging.CursorFor(paging.Key{ID: requests[len(requests)-1].ID, CreatedAt: now.Add(-time.Duration(len(requests)-1) * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	syncer := NewSyncer(store, privateKey, trustedTestCapabilities(), "http://requester.invalid", time.Second, time.Hour)
	syncer.now = func() time.Time { return now }
	syncer.client.Transport = directTransport{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(struct {
			Requests   []model.Request `json:"requests"`
			NextCursor string          `json:"next_cursor,omitempty"`
		}{Requests: requests, NextCursor: nextCursor})
	})}
	if err := syncer.pullRequests(t.Context()); err == nil || !strings.Contains(err.Error(), "failed local validation") {
		t.Fatalf("page with one envelope rejection error=%v", err)
	}
	if syncer.pullCursor != nextCursor || syncer.pullPages != 1 || len(store.state.Requests) != maxPullPageRecords-1 {
		t.Fatalf("envelope rejection stalled page: cursor=%q pages=%d records=%d", syncer.pullCursor, syncer.pullPages, len(store.state.Requests))
	}
}

func TestSyncerRejectsInvalidPendingPagesWithoutAdvancing(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, _ := trustedTestStore(t, privateKey, now)
	requests := pendingSyncRequests(t, now, maxPullPageRecords)
	lastCursor, err := paging.CursorFor(paging.Key{ID: requests[len(requests)-1].ID, CreatedAt: now.Add(-time.Duration(len(requests)-1) * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	olderCursor, err := paging.CursorFor(paging.Key{ID: "req_00000000000000009999", CreatedAt: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	malformed := requests[0]
	malformed.CreatedAt = "not-a-timestamp"
	for name, test := range map[string]struct {
		page   []model.Request
		next   string
		cursor string
		pages  int
	}{
		"empty nonterminal": {nil, lastCursor, "", 0},
		"short nonterminal": {requests[:1], lastCursor, "", 0},
		"mismatched cursor": {requests, olderCursor, "", 0},
		"nonforward cycle":  {requests, lastCursor, lastCursor, 1},
		"oversized":         {append(append([]model.Request(nil), requests...), requests[0]), "", "", 0},
		"malformed":         {[]model.Request{malformed}, "", "", 0},
		"pagination bound":  {requests, lastCursor, "", maxPullPages - 1},
	} {
		t.Run(name, func(t *testing.T) {
			syncer := NewSyncer(store, privateKey, trustedTestCapabilities(), "http://requester.invalid", time.Second, time.Hour)
			syncer.now = func() time.Time { return now }
			syncer.pullCursor, syncer.pullPages = test.cursor, test.pages
			syncer.client.Transport = directTransport{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/pending-requests" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(struct {
					Requests   []model.Request `json:"requests"`
					NextCursor string          `json:"next_cursor,omitempty"`
				}{Requests: test.page, NextCursor: test.next})
			})}
			if err := syncer.pullRequests(t.Context()); err == nil {
				t.Fatal("invalid pending page accepted")
			}
			if syncer.pullCursor != test.cursor || syncer.pullPages != test.pages || len(store.state.Requests) != 0 {
				t.Fatalf("invalid page advanced or ingested: cursor=%q pages=%d records=%d", syncer.pullCursor, syncer.pullPages, len(store.state.Requests))
			}
		})
	}
}

func pendingSyncRequests(t *testing.T, now time.Time, count int) []model.Request {
	t.Helper()
	requests := make([]model.Request, count)
	for index := range requests {
		request := trustedTestRequest(t, now.Add(-time.Duration(index)*time.Second))
		request.ID = fmt.Sprintf("req_%020d", index)
		if err := model.SetRequestDigest(&request); err != nil {
			t.Fatal(err)
		}
		requests[index] = request
	}
	return requests
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
	record, err := requesterStore.Create(requester.CreateInput{ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion, Argv: []string{"api", "repos/example-owner/project"}, Reason: "Enable bounded contribution", TTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := trustedStore.Execute(context.Background(), record.Request.ID, "reviewer@example.invalid", trustedPlanDigest(t, trustedStore, record.Request.ID)); err != nil {
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

func TestTrustedOutputPreviewNeverCrossesRequesterReceiptAPIUIOrMCPBoundary(t *testing.T) {
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
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local IPv4 loopback is unavailable for requester/MCP boundary proof: %v", err)
	}
	requesterHTTP := httptest.NewUnstartedServer(requester.NewServer(requesterStore).Handler())
	requesterHTTP.Listener = listener
	requesterHTTP.Start()
	defer requesterHTTP.Close()
	trustedStore, runner := trustedTestStore(t, privateKey, now)
	runner.preview = ExecutionOutputPreview{Stdout: "trusted-preview " + testOutputCredential, Stderr: "stderr " + testOutputCredential}
	syncer := NewSyncer(trustedStore, privateKey, trustedTestCapabilities(), requesterHTTP.URL, time.Second, time.Hour)
	syncer.now = func() time.Time { return now }
	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	created, err := requesterStore.Create(requester.CreateInput{ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion, Argv: []string{"api", "user"}, Reason: "bounded output boundary", TTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := trustedStore.Execute(context.Background(), created.Request.ID, "reviewer@example.invalid", trustedPlanDigest(t, trustedStore, created.Request.ID)); err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if record, found := requesterStore.Record(created.Request.ID); !found || strings.Contains(mustJSON(t, record), testOutputCredential) {
		t.Fatalf("trusted output crossed requester state: found=%v record=%#v", found, record)
	}
	for _, target := range []string{"/api/v1/requests/" + created.Request.ID, "/"} {
		response, err := http.Get(requesterHTTP.URL + target)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil || strings.Contains(string(body), testOutputCredential) {
			t.Fatalf("trusted output crossed requester %s: %v %q", target, readErr, body)
		}
	}
	requesterClient, err := requester.NewClient(requesterHTTP.URL)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"airlock_requests","arguments":{}}}` + "\n"
	var mcpOutput bytes.Buffer
	if err := mcp.New(requesterClient).Serve(strings.NewReader(request), &mcpOutput); err != nil || strings.Contains(mcpOutput.String(), testOutputCredential) {
		t.Fatalf("trusted output crossed MCP: err=%v output=%q", err, mcpOutput.String())
	}
	runner.err = errors.New("provider " + testOutputCredential)
	second := trustedTestRequest(t, now)
	second.ID = "req_0123456789abcdefghik"
	if err := model.SetRequestDigest(&second); err != nil {
		t.Fatal(err)
	}
	if err := trustedStore.Ingest(second); err != nil {
		t.Fatal(err)
	}
	if err := trustedStore.Execute(context.Background(), second.ID, "reviewer@example.invalid", trustedPlanDigest(t, trustedStore, second.ID)); !errors.Is(err, ErrExecutionUncertain) || strings.Contains(err.Error(), testOutputCredential) {
		t.Fatalf("trusted execution error exposed provider output: %v", err)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

type recordingRunner struct {
	mu                 sync.Mutex
	calls              int
	plan               ExecutionPlan
	env                []string
	err                error
	preview            ExecutionOutputPreview
	started            chan struct{}
	release            <-chan struct{}
	onRun              func()
	ignoreCancellation bool
}

func (r *recordingRunner) Run(ctx context.Context, plan ExecutionPlan, environment []string) (ExecutionOutputPreview, error) {
	r.mu.Lock()
	r.calls++
	r.plan = plan
	r.env = append([]string(nil), environment...)
	started := r.started
	release := r.release
	err := r.err
	preview := r.preview
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
			return preview, err
		}
		select {
		case <-release:
		case <-ctx.Done():
			return preview, ctx.Err()
		}
	}
	return preview, err
}

func (r *recordingRunner) Calls() int { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }

func trustedTestStore(t *testing.T, privateKey ed25519.PrivateKey, now time.Time) (*Store, *recordingRunner) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(dir, "gh-config")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "hosts.yml"), []byte("github.example.invalid:\n  user: test-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dir, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, trustedTestExecutionConfig(configDir))
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
	request := model.Request{Version: model.RequestVersionV1, ID: "req_0123456789abcdefghij", CapabilityID: "github:example-owner", Action: model.ActionGitHubAddCollaborator, Arguments: map[string]string{"repository": "project", "permission": "push"}, Reason: "Enable a bounded contribution", CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(10 * time.Minute)), Nonce: "0123456789abcdefghijklmnopqrstuv"}
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

func trustedTestExecutionConfig(configDir string) ExecutionConfig {
	return ExecutionConfig{GitHubCLIPath: "/trusted/fake/gh", GitHubConfigDir: configDir, SandboxCLIPath: "/usr/bin/bwrap", ExecutableSHA256: strings.Repeat("a", 64), Timeout: time.Minute, Profile: model.CommandProfile{ID: model.ProfileGitHubCommandID, Version: model.ProfileGitHubCommandVersion, DisplayName: "GitHub CLI command", AuthorityLabel: "Broad GitHub authority", SandboxLabel: "Ephemeral local state", NetworkLabel: "GitHub network", CWDLabel: "Ephemeral directory", OutputLabel: "Bounded sanitized trusted-local output preview", Limits: model.ProfileLimits{MaxArgvCount: model.MaxArgvCount, MaxArgumentBytes: model.MaxArgumentBytes, MaxAggregateBytes: model.MaxArgvAggregateBytes}}, ProfileConfigVersion: "test-v1", ExecutionIdentity: "trusted test identity", sandboxLauncherDigestForTest: strings.Repeat("b", 64)}
}

func trustedPlanDigest(t *testing.T, store *Store, id string) string {
	t.Helper()
	_, plan, found := store.Record(id)
	if !found || plan == nil {
		record, _, _ := store.Record(id)
		_, resolveErr := resolveExecutionPlan(record.Request, store.capabilities, actionTime(record.Request), store.requestMaxTTL, store.execution)
		t.Fatalf("resolved plan unavailable for %s: %v", id, resolveErr)
	}
	return plan.Digest
}
