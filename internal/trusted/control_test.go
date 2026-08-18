package trusted

import (
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
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/donovan-yohan/airlock/internal/model"
)

func TestControlPlaneSocketLifecycleAndUnsafePaths(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := trustedTestStore(t, privateKey, time.Now().UTC().Truncate(time.Second))
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "control.sock")
	plane, err := NewControlPlane(socket, NewActionService(store))
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("execution sandbox does not permit Unix-domain sockets")
		}
		if strings.Contains(err.Error(), "requires Linux SO_PEERCRED") {
			t.Skip("control socket is intentionally Linux-only")
		}
		t.Fatal(err)
	}
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("control socket mode=%v err=%v", info.Mode(), err)
	}
	lockInfo, err := os.Lstat(socket + ".lock")
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("control lifecycle lock mode=%v err=%v", lockInfo.Mode(), err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("control directory mode=%v err=%v", dirInfo.Mode(), err)
	}
	done := make(chan error, 1)
	go func() { done <- plane.Serve() }()
	client, err := NewControlClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.List(context.Background(), "")
	if err != nil || len(page.Requests) != 0 {
		t.Fatalf("same-UID control request page=%#v err=%v", page, err)
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := plane.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("control socket remained after shutdown: %v", err)
	}
	restarted, err := NewControlPlane(socket, NewActionService(store))
	if err != nil {
		t.Fatalf("control lifecycle lock remained after shutdown: %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}

	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewControlPlane(regular, NewActionService(store)); err == nil {
		t.Fatal("regular control path was accepted")
	}
	if contents, err := os.ReadFile(regular); err != nil || string(contents) != "do not replace" {
		t.Fatalf("unsafe control path changed: %q %v", contents, err)
	}
	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := NewControlPlane(symlink, NewActionService(store)); err == nil {
		t.Fatal("symlink control path was accepted")
	}

	stale := filepath.Join(dir, "stale.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); err != nil {
		t.Fatalf("test did not retain a stale Unix socket: %v", err)
	}
	stalePlane, err := NewControlPlane(stale, NewActionService(store))
	if err != nil {
		t.Fatalf("stale control socket was not cleaned safely: %v", err)
	}
	if err := stalePlane.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestControlPlaneLifecycleLockRejectsConcurrentStartWithoutDisruptingActivePlane(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := trustedTestStore(t, privateKey, time.Now().UTC().Truncate(time.Second))
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "control.sock")
	plane, err := NewControlPlane(socket, NewActionService(store))
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("execution sandbox does not permit Unix-domain sockets")
		}
		if strings.Contains(err.Error(), "requires Linux SO_PEERCRED") {
			t.Skip("control socket is intentionally Linux-only")
		}
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- plane.Serve() }()
	t.Cleanup(func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := plane.Shutdown(shutdownContext); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})

	client, err := NewControlClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.List(context.Background(), ""); err != nil {
		t.Fatalf("active control plane was unreachable before concurrent start: %v", err)
	}
	if _, err := NewControlPlane(socket, NewActionService(store)); err == nil {
		t.Fatal("second control plane acquired the active lifecycle lock")
	}
	if info, err := os.Lstat(socket); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("concurrent start disrupted active control socket mode=%v err=%v", info.Mode(), err)
	}
	if _, err := client.List(context.Background(), ""); err != nil {
		t.Fatalf("active control plane was unreachable after concurrent start: %v", err)
	}
}

func TestControlPlaneLifecycleLockRejectsUnsafePath(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := trustedTestStore(t, privateKey, time.Now().UTC().Truncate(time.Second))
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "control.sock")
	lock := socket + ".lock"
	if err := os.WriteFile(lock, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lock, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewControlPlane(socket, NewActionService(store)); err == nil {
		t.Fatal("group-readable lifecycle lock was accepted")
	}
	if contents, err := os.ReadFile(lock); err != nil || string(contents) != "do not replace" {
		t.Fatalf("unsafe lifecycle lock changed: %q %v", contents, err)
	}

	target := filepath.Join(dir, "lock-target")
	if err := os.WriteFile(target, []byte("do not follow"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, lock); err != nil {
		t.Fatal(err)
	}
	if _, err := NewControlPlane(socket, NewActionService(store)); err == nil {
		t.Fatal("symlink lifecycle lock was accepted")
	}
	if contents, err := os.ReadFile(target); err != nil || string(contents) != "do not follow" {
		t.Fatalf("lifecycle lock symlink target changed: %q %v", contents, err)
	}
}

func TestControlPeerUIDAuthorization(t *testing.T) {
	const trustedUID = uint32(4242)
	if !controlPeerUIDAuthorized(trustedUID, trustedUID) {
		t.Fatal("same UID was rejected")
	}
	if controlPeerUIDAuthorized(trustedUID+1, trustedUID) {
		t.Fatal("different UID was accepted")
	}
}

func TestControlResponseDeadlineCoversConfiguredExecution(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := trustedTestStore(t, privateKey, time.Now().UTC().Truncate(time.Second))
	store.execution.Timeout = 3 * time.Minute
	if got, want := controlWriteTimeout(NewActionService(store)), 3*time.Minute+controlResponseGrace; got != want {
		t.Fatalf("control write timeout=%s want=%s", got, want)
	}
	if maxControlCallTime <= 5*time.Minute {
		t.Fatal("control client deadline cannot cancel the largest allowed execution")
	}
}

func TestControlPlaneRejectsUnsafeExistingPaths(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := trustedTestStore(t, privateKey, time.Now().UTC().Truncate(time.Second))
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewControlPlane(regular, NewActionService(store)); err == nil {
		t.Fatal("regular control path was accepted")
	}
	if contents, err := os.ReadFile(regular); err != nil || string(contents) != "do not replace" {
		t.Fatalf("unsafe control path changed: %q %v", contents, err)
	}
	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := NewControlPlane(symlink, NewActionService(store)); err == nil {
		t.Fatal("symlink control path was accepted")
	}
}

func TestControlRoutesAreBoundedAndCannotSpoofReviewer(t *testing.T) {
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
	server := NewControlServer(NewActionService(store))
	handler := server.Handler()
	assertControlStatus(t, handler, http.MethodPost, "/v1/requests", nil, nil, http.StatusMethodNotAllowed)
	assertControlStatus(t, handler, http.MethodGet, "/v1/requests", strings.NewReader("x"), nil, http.StatusBadRequest)
	assertControlStatus(t, handler, http.MethodGet, "/v1/requests?limit=1", nil, nil, http.StatusBadRequest)
	assertControlStatus(t, handler, http.MethodGet, "/v1/requests/"+strings.Repeat("a", 100), nil, nil, http.StatusBadRequest)
	assertControlStatus(t, handler, http.MethodPost, "/v1/requests/"+request.ID+"/execute", strings.NewReader("{}"), map[string]string{"Content-Type": "text/plain"}, http.StatusUnsupportedMediaType)
	assertControlStatus(t, handler, http.MethodPost, "/v1/requests/"+request.ID+"/execute?x=1", strings.NewReader("{}"), map[string]string{"Content-Type": "application/json"}, http.StatusBadRequest)
	assertControlStatus(t, handler, http.MethodPost, "/v1/requests/"+request.ID+"/execute", strings.NewReader(`{"reviewer":"attacker@example.invalid"}`), map[string]string{"Content-Type": "application/json"}, http.StatusBadRequest)
	assertControlStatus(t, handler, http.MethodPost, "/v1/requests/"+request.ID+"/execute", strings.NewReader("{"+strings.Repeat("x", maxControlBodyBytes)+"}"), map[string]string{"Content-Type": "application/json"}, http.StatusRequestEntityTooLarge)

	response := httptest.NewRecorder()
	// A digest alone is intentionally insufficient, even for a same-UID local
	// caller. The control protocol carries the second explicit confirmation.
	digest := trustedPlanDigest(t, store, request.ID)
	assertControlStatus(t, handler, http.MethodPost, "/v1/requests/"+request.ID+"/execute", strings.NewReader(`{"plan_digest":"`+digest+`"}`), map[string]string{"Content-Type": "application/json"}, http.StatusBadRequest)
	assertControlStatus(t, handler, http.MethodPost, "/v1/requests/"+request.ID+"/execute", strings.NewReader(`{"plan_digest":"`+digest+`","confirm_full_authority":false}`), map[string]string{"Content-Type": "application/json"}, http.StatusBadRequest)
	assertControlStatus(t, handler, http.MethodPost, "/v1/requests/"+request.ID+"/execute", strings.NewReader(`{"plan_digest":"`+digest+`","confirm_full_authority":true,"confirm_full_authority":true}`), map[string]string{"Content-Type": "application/json"}, http.StatusBadRequest)
	body, _ := json.Marshal(map[string]any{"plan_digest": digest, "confirm_full_authority": true})
	handler.ServeHTTP(response, controlHTTP(t, http.MethodPost, "/v1/requests/"+request.ID+"/execute", strings.NewReader(string(body)), map[string]string{
		"Content-Type": "application/json", "X-Airlock-Dev-Identity": "attacker@example.invalid", "Tailscale-User-Login": "attacker@example.invalid",
	}))
	if response.Code != http.StatusOK || runner.Calls() != 1 {
		t.Fatalf("control execute status=%d calls=%d body=%q", response.Code, runner.Calls(), response.Body.String())
	}
	record, _, found := store.Record(request.ID)
	if !found || record.Attempts[0].Reviewer != server.reviewer || strings.Contains(record.Attempts[0].Reviewer, "attacker") {
		t.Fatalf("control caller selected a reviewer: %#v", record.Attempts)
	}
}

func TestControlListAndShowAreSanitized(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, _ := trustedTestStore(t, privateKey, now)
	request := trustedTestRequest(t, now)
	request.Reason = "credential-canary-do-not-return"
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	handler := NewControlServer(NewActionService(store)).Handler()
	for _, target := range []string{"/v1/requests", "/v1/requests/" + request.ID} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, controlHTTP(t, http.MethodGet, target, nil, nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "credential-canary-do-not-return") || !strings.Contains(response.Body.String(), `"reason"`) {
			t.Fatalf("trusted control response omitted canonical review data: %d %q", response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"plan"`) {
			t.Fatalf("control response omitted trusted plan: %q", response.Body.String())
		}
		for _, field := range []string{`"credential_source_id"`, `"sandbox_launcher"`, `"sandbox_launcher_sha256"`, `"environment_policy"`} {
			if !strings.Contains(response.Body.String(), field) {
				t.Fatalf("control response omitted trusted plan binding %s: %q", field, response.Body.String())
			}
		}
	}
}

func TestControlClientFollowsStrictNextCursor(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, _ := trustedTestStore(t, privateKey, now)
	for index := 0; index <= maxControlPageRecords; index++ {
		request := trustedTestRequest(t, now)
		request.ID = fmt.Sprintf("req_%020d", index)
		if err := model.SetRequestDigest(&request); err != nil {
			t.Fatal(err)
		}
		if err := store.Ingest(request); err != nil {
			t.Fatal(err)
		}
	}
	client := controlClientFor(NewControlServer(NewActionService(store)).Handler())
	page, err := client.List(context.Background(), "")
	if err != nil || len(page.Requests) != maxControlPageRecords || page.NextCursor == "" {
		t.Fatalf("first control page=%#v err=%v", page, err)
	}
	next, err := client.List(context.Background(), page.NextCursor)
	if err != nil || len(next.Requests) != 1 || next.NextCursor != "" {
		t.Fatalf("next control page=%#v err=%v", next, err)
	}
	if _, err := client.List(context.Background(), "not-a-cursor"); err == nil {
		t.Fatal("invalid control cursor reached the daemon")
	}
}

func TestMaximumCurrentCommandControlResponsesFitClientBudget(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	executable := "/" + strings.Repeat("<", maxExecutionPathBytes-1)
	if !validExecutionPath(executable) {
		t.Fatal("maximum escaped executable path was rejected")
	}
	for _, unsafe := range []string{"/trusted/\u200bgh", "/trusted/\ufdd0gh"} {
		if validExecutionPath(unsafe) {
			t.Fatalf("invisible trusted execution path was accepted: %q", unsafe)
		}
	}
	store.execution.GitHubCLIPath = executable
	store.execution.Profile.AuthorityLabel = strings.Repeat("<", 200)
	store.execution.Profile.SandboxLabel = strings.Repeat("<", 200)
	store.execution.Profile.NetworkLabel = strings.Repeat("<", 200)
	store.execution.Profile.CWDLabel = strings.Repeat("<", 200)
	store.execution.Profile.OutputLabel = strings.Repeat("<", 200)
	store.execution.ExecutionIdentity = strings.Repeat("<", 200)
	store.execution.ProfileConfigVersion = strings.Repeat("p", 64)
	reviewer := strings.Repeat("<", 254)
	request := currentCommandRequest(t, now, "req_0123456789abcdefghij", maximalControlArgv())
	request.Reason = strings.Repeat("r ", model.MaxReasonBytes/2)
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < maxExecutionAttempts-1; attempt++ {
		runner.err = errors.New("synthetic provider failure")
		runner.preview = ExecutionOutputPreview{Stdout: strings.Repeat(`"`, maxExecutionOutputPreviewBytes), Stderr: strings.Repeat(`\`, maxExecutionOutputPreviewBytes)}
		if err := store.Execute(context.Background(), request.ID, reviewer, trustedPlanDigest(t, store, request.ID)); !errors.Is(err, ErrExecutionUncertain) {
			t.Fatalf("ambiguous execution %d: %v", attempt, err)
		}
	}
	handler := NewControlServer(NewActionService(store)).Handler()
	client := controlClientFor(handler)
	runner.err = nil
	runner.preview = ExecutionOutputPreview{Stdout: strings.Repeat(`"`, maxExecutionOutputPreviewBytes), Stderr: strings.Repeat(`\`, maxExecutionOutputPreviewBytes)}
	if action, err := client.Execute(context.Background(), request.ID, trustedPlanDigest(t, store, request.ID), true); err != nil || action.Outcome != model.DecisionExecuted {
		t.Fatalf("maximal execute response=%#v err=%v", action, err)
	}

	denied := currentCommandRequest(t, now, "req_0123456789abcdefghik", maximalControlArgv())
	denied.Reason = strings.Repeat(`"`, model.MaxReasonBytes)
	if err := model.SetRequestDigest(&denied); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(denied); err != nil {
		t.Fatal(err)
	}
	if action, err := client.Deny(context.Background(), denied.ID); err != nil || action.Outcome != "denied" {
		t.Fatalf("maximal deny response=%#v err=%v", action, err)
	}
	if record, err := client.Show(context.Background(), request.ID); err != nil || len(record.Attempts) != maxExecutionAttempts {
		t.Fatalf("maximal show response=%#v err=%v", record, err)
	}
	page, err := client.List(context.Background(), "")
	if err != nil || len(page.Requests) != maxControlPageRecords || page.NextCursor == "" {
		t.Fatalf("maximum control page parse=%#v err=%v", page, err)
	}
	for _, target := range []string{"/v1/requests", "/v1/requests/" + request.ID} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, controlHTTP(t, http.MethodGet, target, nil, nil))
		if response.Code != http.StatusOK || response.Body.Len() > maxControlJSONBytes || !strings.Contains(response.Body.String(), `\"`) {
			t.Fatalf("maximum control %s status=%d bytes=%d", target, response.Code, response.Body.Len())
		}
	}
}

func maximalControlArgv() []string {
	argv := make([]string, model.MaxArgvCount)
	for index := range argv {
		argv[index] = strings.Repeat(`"`, model.MaxArgvAggregateBytes/model.MaxArgvCount)
	}
	return argv
}

func TestControlResponsesNeverExceedClientLimit(t *testing.T) {
	overLimit := strings.Repeat("x", maxControlJSONBytes)
	page := ControlPage{Requests: []ControlRecord{{Plan: &ControlPlan{EscapedDisplay: overLimit}}}}
	record := ControlRecord{Plan: &ControlPlan{EscapedDisplay: overLimit}}
	for name, value := range map[string]any{"page": page, "record": record} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			controlWrite(response, http.StatusOK, value)
			if response.Code != http.StatusInternalServerError || response.Body.Len() > maxControlJSONBytes {
				t.Fatalf("oversized %s response status=%d bytes=%d", name, response.Code, response.Body.Len())
			}
		})
	}
}

func TestWebAndControlExecuteShareOneServiceAndReservation(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	service := NewActionService(store)
	web, err := NewServerWithActionService(service, []string{"reviewer@example.invalid"}, true)
	if err != nil {
		t.Fatal(err)
	}
	client := controlClientFor(NewControlServer(service).Handler())
	if _, err := client.Execute(context.Background(), "req_0123456789abcdefghik", strings.Repeat("a", 64), false); !errors.Is(err, ErrExecutionConfirmationRequired) {
		t.Fatalf("control client accepted absent confirmation: %v", err)
	}

	webRequest := trustedTestRequest(t, now)
	controlRequestObject := trustedTestRequest(t, now)
	controlRequestObject.ID = "req_0123456789abcdefghik"
	if err := model.SetRequestDigest(&controlRequestObject); err != nil {
		t.Fatal(err)
	}
	for _, request := range []model.Request{webRequest, controlRequestObject} {
		if err := store.Ingest(request); err != nil {
			t.Fatal(err)
		}
	}
	if err := webExecute(t, web.Handler(), web, webRequest.ID); err != nil {
		t.Fatal(err)
	}
	result, err := client.Execute(context.Background(), controlRequestObject.ID, trustedPlanDigest(t, store, controlRequestObject.ID), true)
	if err != nil || result.Outcome != "executed" {
		t.Fatalf("control execution result=%#v err=%v", result, err)
	}
	if runner.Calls() != 2 {
		t.Fatalf("web and control did not use the same executor: %d", runner.Calls())
	}
	for range 2 {
		<-runner.started
	}

	concurrent := trustedTestRequest(t, now)
	concurrent.ID = "req_0123456789abcdefghil"
	if err := model.SetRequestDigest(&concurrent); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(concurrent); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	runner.release = release
	webDone := make(chan error, 1)
	go func() { webDone <- webExecute(t, web.Handler(), web, concurrent.ID) }()
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("web execution did not reserve the provider call")
	}
	concurrentResult, err := client.Execute(context.Background(), concurrent.ID, trustedPlanDigest(t, store, concurrent.ID), true)
	if err != nil || concurrentResult.Outcome != attemptStatusRunning || concurrentResult.Request.State != attemptStatusRunning {
		t.Fatalf("concurrent control execution did not report the active persisted state: %#v err=%v", concurrentResult, err)
	}
	close(release)
	if err := <-webDone; err != nil {
		t.Fatal(err)
	}
	if runner.Calls() != 3 {
		t.Fatalf("concurrent web/control execution invoked provider %d times", runner.Calls())
	}
}

func TestWebExecutionRequiresExactlyOneExplicitFullAuthorityConfirmation(t *testing.T) {
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
	server, err := NewServerWithActionService(NewActionService(store), []string{"reviewer@example.invalid"}, true)
	if err != nil {
		t.Fatal(err)
	}
	get := trustedRequest(t, http.MethodGet, "/requests/"+request.ID, nil, nil)
	get.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
	review := httptest.NewRecorder()
	server.Handler().ServeHTTP(review, get)
	if review.Code != http.StatusOK || !strings.Contains(review.Body.String(), `name="confirm_full_authority"`) {
		t.Fatalf("review does not present explicit confirmation: status=%d body=%q", review.Code, review.Body.String())
	}
	plan := trustedPlanDigest(t, store, request.ID)
	for name, form := range map[string]url.Values{
		"absent":     {"csrf_token": {server.csrf}, "plan_digest": {plan}},
		"false":      {"csrf_token": {server.csrf}, "plan_digest": {plan}, "confirm_full_authority": {"false"}},
		"duplicate":  {"csrf_token": {server.csrf}, "plan_digest": {plan}, "confirm_full_authority": {"true", "true"}},
		"unexpected": {"csrf_token": {server.csrf}, "plan_digest": {plan}, "confirm_full_authority": {"yes"}},
	} {
		t.Run(name, func(t *testing.T) {
			post := trustedRequest(t, http.MethodPost, "/requests/"+request.ID+"/execute", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
			post.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
			post.AddCookie(review.Result().Cookies()[0])
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, post)
			if response.Code < http.StatusBadRequest || response.Code >= http.StatusInternalServerError {
				t.Fatalf("confirmation %s status=%d", name, response.Code)
			}
		})
	}
	if runner.Calls() != 0 {
		t.Fatal("unconfirmed web form reached provider")
	}
}

func TestControlDenyAndAmbiguousOutputDoNotLeak(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	service := NewActionService(store)
	client := controlClientFor(NewControlServer(service).Handler())
	denied := trustedTestRequest(t, now)
	if err := store.Ingest(denied); err != nil {
		t.Fatal(err)
	}
	denial, err := client.Deny(context.Background(), denied.ID)
	if err != nil || denial.Outcome != "denied" || denial.Request.State != "denied" {
		t.Fatalf("control deny result=%#v err=%v", denial, err)
	}
	if err := service.Execute(context.Background(), denied.ID, "reviewer@example.invalid", strings.Repeat("a", 64), true); !errors.Is(err, ErrExecutionRejected) {
		t.Fatalf("deny did not share terminal store transition: %v", err)
	}

	canary := "raw-provider-output-and-credential-canary"
	request := trustedTestRequest(t, now)
	request.ID = "req_0123456789abcdefghim"
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	runner.err = errors.New(canary)
	result, err := client.Execute(context.Background(), request.ID, trustedPlanDigest(t, store, request.ID), true)
	if err != nil || result.Outcome != attemptStatusUncertain {
		t.Fatalf("ambiguous control result=%#v err=%v", result, err)
	}
	state, _ := json.Marshal(store.state)
	if strings.Contains(string(state), canary) {
		t.Fatal("provider canary leaked to trusted state")
	}
	if encoded, err := json.Marshal(result); err != nil || strings.Contains(string(encoded), canary) {
		t.Fatalf("provider canary leaked to control response: %v", err)
	}
	web, err := NewServerWithActionService(service, []string{"reviewer@example.invalid"}, true)
	if err != nil {
		t.Fatal(err)
	}
	review := httptest.NewRecorder()
	req := trustedRequest(t, http.MethodGet, "/requests/"+request.ID, nil, nil)
	req.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
	web.Handler().ServeHTTP(review, req)
	if strings.Contains(review.Body.String(), canary) {
		t.Fatal("provider canary leaked to trusted UI")
	}
}

func TestSanitizedOutputPreviewStaysOnTrustedReviewSurfaces(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	runner.preview = ExecutionOutputPreview{Stdout: "trusted-local-preview", Stderr: "sanitized-stderr", StdoutTruncated: true, Redacted: true}
	request := trustedTestRequest(t, now)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	service := NewActionService(store)
	if err := service.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID), true); err != nil {
		t.Fatal(err)
	}
	record, _, found := store.Record(request.ID)
	if !found || len(record.Attempts) != 1 || record.Attempts[0].OutputPreview == nil || record.Attempts[0].OutputPreview.Stdout != "trusted-local-preview"+outputTruncationMarker {
		t.Fatalf("trusted preview was not retained locally: %#v", record)
	}
	control := NewControlServer(service).sanitize(record)
	controlRaw, err := json.Marshal(control)
	if err != nil || !strings.Contains(string(controlRaw), "trusted-local-preview") || !strings.Contains(string(controlRaw), `"local_only":true`) {
		t.Fatalf("trusted preview was not marked in control projection: %v %q", err, controlRaw)
	}
	client := controlClientFor(NewControlServer(service).Handler())
	shown, err := client.Show(context.Background(), request.ID)
	if err != nil || len(shown.Attempts) != 1 || shown.Attempts[0].OutputPreview == nil || !shown.Attempts[0].OutputPreview.LocalOnly || shown.Attempts[0].OutputPreview.Stdout != "trusted-local-preview"+outputTruncationMarker || !shown.Attempts[0].OutputPreview.Redacted || !shown.Attempts[0].OutputPreview.StdoutTruncated {
		t.Fatalf("trusted CLI/control preview projection=%#v err=%v", shown, err)
	}
	receiptsRaw, err := json.Marshal(record.Receipts)
	if err != nil || strings.Contains(string(receiptsRaw), "trusted-local-preview") {
		t.Fatalf("trusted preview crossed receipt boundary: %v %q", err, receiptsRaw)
	}
	web, err := NewServerWithActionService(service, []string{"reviewer@example.invalid"}, true)
	if err != nil {
		t.Fatal(err)
	}
	review := httptest.NewRecorder()
	get := trustedRequest(t, http.MethodGet, "/requests/"+request.ID, nil, nil)
	get.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
	web.Handler().ServeHTTP(review, get)
	for _, required := range []string{"trusted-local-preview", "sanitized-stderr", "Visible only to this trusted reviewer surface", "credential-like text redacted", "stdout truncated"} {
		if !strings.Contains(review.Body.String(), required) {
			t.Fatalf("trusted web preview missing %q: %q", required, review.Body.String())
		}
	}
}

func TestRetryGetsCurrentPlanWhileHistoryKeepsApprovedPlansAcrossConfigDrift(t *testing.T) {
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
	firstDigest := trustedPlanDigest(t, store, request.ID)
	runner.err = errors.New("synthetic provider ambiguity")
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", firstDigest); !errors.Is(err, ErrExecutionUncertain) {
		t.Fatalf("first execution=%v", err)
	}
	store.execution.ProfileConfigVersion = "test-v2"
	retryRecord, retryPlan, found := store.Record(request.ID)
	if !found || retryPlan == nil || retryPlan.ProfileConfigVersion != "test-v2" || retryPlan.Digest == firstDigest {
		t.Fatalf("retry did not receive a fresh drift-checked plan: record=%#v plan=%#v", retryRecord, retryPlan)
	}
	control := NewControlServer(NewActionService(store)).sanitize(retryRecord)
	if control.Plan == nil || control.Plan.ProfileConfigVersion != "test-v2" || len(control.Attempts) != 1 || control.Attempts[0].Plan == nil || control.Attempts[0].Plan.ProfileConfigVersion != "test-v1" || control.Attempts[0].Plan.PlanDigest != firstDigest {
		t.Fatalf("control mixed current retry and immutable history: %#v", control)
	}
	runner.err = nil
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", retryPlan.Digest); err != nil {
		t.Fatalf("fresh explicit retry=%v", err)
	}
	store.execution.ProfileConfigVersion = "test-v3"
	completed, displayedPlan, found := store.Record(request.ID)
	if !found || displayedPlan == nil || displayedPlan.ProfileConfigVersion != "test-v2" || len(completed.Attempts) != 2 || completed.Attempts[0].Plan == nil || completed.Attempts[1].Plan == nil || completed.Attempts[0].Plan.ProfileConfigVersion != "test-v1" || completed.Attempts[1].Plan.ProfileConfigVersion != "test-v2" {
		t.Fatalf("post-execution history was re-resolved instead of using approved plans: record=%#v plan=%#v", completed, displayedPlan)
	}
	control = NewControlServer(NewActionService(store)).sanitize(completed)
	if control.Plan == nil || control.Plan.ProfileConfigVersion != "test-v2" || len(control.Attempts) != 2 || control.Attempts[0].Plan == nil || control.Attempts[1].Plan == nil || control.Attempts[0].Plan.ProfileConfigVersion != "test-v1" || control.Attempts[1].Plan.ProfileConfigVersion != "test-v2" {
		t.Fatalf("control history lost immutable plans after later drift: %#v", control)
	}
	web, err := NewServer(store, []string{"reviewer@example.invalid"}, true)
	if err != nil {
		t.Fatal(err)
	}
	review := httptest.NewRecorder()
	get := trustedRequest(t, http.MethodGet, "/requests/"+request.ID, nil, nil)
	get.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
	web.Handler().ServeHTTP(review, get)
	for _, required := range []string{"Immutable plan approved for this attempt", firstDigest, retryPlan.Digest, "test-v1", "test-v2"} {
		if !strings.Contains(review.Body.String(), required) {
			t.Fatalf("trusted web history omitted %q: %q", required, review.Body.String())
		}
	}
	if strings.Contains(review.Body.String(), "test-v3") {
		t.Fatalf("trusted web history silently re-resolved after execution: %q", review.Body.String())
	}
}

func controlClientFor(handler http.Handler) *ControlClient {
	return &ControlClient{client: &http.Client{Transport: directTransport{handler: handler}}}
}

func webExecute(t *testing.T, handler http.Handler, server *Server, id string) error {
	t.Helper()
	review := trustedRequest(t, http.MethodGet, "/requests/"+id, nil, nil)
	review.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
	reviewResponse := httptest.NewRecorder()
	handler.ServeHTTP(reviewResponse, review)
	if reviewResponse.Code != http.StatusOK || len(reviewResponse.Result().Cookies()) != 1 {
		return errors.New("trusted web review was unavailable")
	}
	_, plan, found := server.service.Record(id)
	if !found || plan == nil {
		return errors.New("trusted plan was unavailable")
	}
	form := url.Values{"csrf_token": {server.csrf}, "plan_digest": {plan.Digest}, "confirm_full_authority": {"true"}}.Encode()
	post := trustedRequest(t, http.MethodPost, "/requests/"+id+"/execute", strings.NewReader(form), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	post.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
	post.AddCookie(reviewResponse.Result().Cookies()[0])
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, post)
	if response.Code != http.StatusSeeOther {
		return errors.New("trusted web execution was rejected")
	}
	return nil
}

func assertControlStatus(t *testing.T, handler http.Handler, method, target string, body io.Reader, headers map[string]string, want int) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, controlHTTP(t, method, target, body, headers))
	if response.Code != want {
		t.Fatalf("%s %s status=%d want=%d body=%q", method, target, response.Code, want, response.Body.String())
	}
}

func controlHTTP(t *testing.T, method, target string, body io.Reader, headers map[string]string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, target, body)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	return request
}
