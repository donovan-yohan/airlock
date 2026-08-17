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
	handler.ServeHTTP(response, controlHTTP(t, http.MethodPost, "/v1/requests/"+request.ID+"/execute", strings.NewReader("{}"), map[string]string{
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
		if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "credential-canary-do-not-return") || strings.Contains(response.Body.String(), `"reason"`) {
			t.Fatalf("control response exposed unsanitized request data: %d %q", response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"plan"`) {
			t.Fatalf("control response omitted trusted plan: %q", response.Body.String())
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

func TestMaximumValidControlPageFitsClientBudget(t *testing.T) {
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
	store.execution.GitHubCLIPath = executable
	reviewer := strings.Repeat("<", 254)
	for index := 0; index < maxControlPageRecords; index++ {
		request := trustedTestRequest(t, now)
		request.ID = fmt.Sprintf("req_%079d%d", 0, index)
		request.Arguments["repository"] = strings.Repeat("a", 100)
		if err := model.SetRequestDigest(&request); err != nil {
			t.Fatal(err)
		}
		if err := store.Ingest(request); err != nil {
			t.Fatal(err)
		}
		for attempt := 0; attempt < maxExecutionAttempts; attempt++ {
			runner.err = errors.New("synthetic provider failure")
			if attempt == maxExecutionAttempts-1 {
				runner.err = nil
			}
			err := store.Execute(context.Background(), request.ID, reviewer)
			if attempt == maxExecutionAttempts-1 {
				if err != nil {
					t.Fatalf("final execution %d: %v", index, err)
				}
			} else if !errors.Is(err, ErrExecutionUncertain) {
				t.Fatalf("ambiguous execution %d/%d: %v", index, attempt, err)
			}
		}
	}
	handler := NewControlServer(NewActionService(store)).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, controlHTTP(t, http.MethodGet, "/v1/requests", nil, nil))
	if response.Code != http.StatusOK || response.Body.Len() > maxControlJSONBytes {
		t.Fatalf("maximum control page status=%d bytes=%d", response.Code, response.Body.Len())
	}
	page, err := controlClientFor(handler).List(context.Background(), "")
	if err != nil || len(page.Requests) != maxControlPageRecords || page.NextCursor != "" {
		t.Fatalf("maximum control page parse=%#v err=%v", page, err)
	}
}

func TestControlResponsesNeverExceedClientLimit(t *testing.T) {
	overLimit := strings.Repeat("x", maxControlJSONBytes)
	page := ControlPage{Requests: []ControlRecord{{Plan: &ControlPlan{Display: overLimit}}}}
	record := ControlRecord{Plan: &ControlPlan{Display: overLimit}}
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
	result, err := client.Execute(context.Background(), controlRequestObject.ID)
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
	concurrentResult, err := client.Execute(context.Background(), concurrent.ID)
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
	if err := service.Execute(context.Background(), denied.ID, "reviewer@example.invalid"); !errors.Is(err, ErrExecutionRejected) {
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
	result, err := client.Execute(context.Background(), request.ID)
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
	post := trustedRequest(t, http.MethodPost, "/requests/"+id+"/execute", strings.NewReader("csrf_token="+server.csrf), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
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
