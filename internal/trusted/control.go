package trusted

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/donovan-yohan/airlock/internal/httpjson"
	"github.com/donovan-yohan/airlock/internal/jsonstrict"
	"github.com/donovan-yohan/airlock/internal/model"
	"github.com/donovan-yohan/airlock/internal/paging"
	"github.com/donovan-yohan/airlock/internal/statefile"
)

const (
	maxControlBodyBytes  = 1024
	maxControlQueryBytes = 512
	// 768 KiB contains one maximal request with its current plan, four immutable
	// attempt plans, four bounded stdout/stderr previews, and receipt history,
	// including JSON's worst-case printable quote/backslash escaping.
	// Pages deliberately contain one record; clients enforce the same cap.
	maxControlJSONBytes = 768 << 10
	// More records must be obtained through the cursor.
	maxControlPageRecords = 1
	controlResponseGrace  = 10 * time.Second
	maxControlCallTime    = 5*time.Minute + controlResponseGrace
)

// ControlPlane is a same-UID Unix-socket HTTP server. It is intentionally
// separate from the TCP/Tailnet web listener. Linux verifies each accepted
// peer's SO_PEERCRED before HTTP can read from the connection; filesystem modes
// remain a separate defense around the socket path.
type ControlPlane struct {
	socket   string
	listener net.Listener
	server   *http.Server
	lock     *os.File

	cleanupOnce sync.Once
	cleanupErr  error
}

func NewControlPlane(socket string, service *ActionService) (*ControlPlane, error) {
	if service == nil {
		return nil, errors.New("trusted action service is required")
	}
	if err := requireControlPeerAuthentication(); err != nil {
		return nil, err
	}
	if socket == "" || !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return nil, errors.New("trusted control socket path is invalid")
	}
	// Validate the trusted state directory before creating its lock file. The
	// lock then covers every inspection, dial, cleanup, and bind of socket.
	if err := statefile.EnsurePrivateDir(filepath.Dir(socket)); err != nil {
		return nil, fmt.Errorf("prepare trusted control socket directory: %w", err)
	}
	if err := validateControlSocketParent(socket); err != nil {
		return nil, err
	}
	lock, err := acquireControlLifecycleLock(socket)
	if err != nil {
		return nil, err
	}
	keepLock := false
	defer func() {
		if !keepLock {
			_ = releaseControlLifecycleLock(lock)
		}
	}()
	if err := prepareControlSocket(socket); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen on trusted control socket: %w", err)
	}
	peerAuthenticatedListener, err := newPeerAuthenticatedControlListener(listener, os.Geteuid())
	if err != nil {
		_ = listener.Close()
		_ = removeControlSocket(socket)
		return nil, fmt.Errorf("enable trusted control peer authentication: %w", err)
	}
	listener = peerAuthenticatedListener
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = listener.Close()
		_ = removeControlSocket(socket)
		return nil, fmt.Errorf("set trusted control socket mode: %w", err)
	}
	plane := &ControlPlane{
		socket: socket, listener: listener, lock: lock,
		server: &http.Server{
			Handler:           NewControlServer(service).Handler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      controlWriteTimeout(service),
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    8 << 10,
		},
	}
	keepLock = true
	return plane, nil
}

func controlPeerUIDAuthorized(peerUID, trustedUID uint32) bool {
	return peerUID == trustedUID
}

func controlWriteTimeout(service *ActionService) time.Duration {
	if service.store.execution != nil {
		return service.store.execution.Timeout + controlResponseGrace
	}
	return maxControlCallTime
}

func (p *ControlPlane) Serve() error {
	err := p.server.Serve(p.listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (p *ControlPlane) Shutdown(ctx context.Context) error {
	err := p.server.Shutdown(ctx)
	if closeErr := p.listener.Close(); err == nil && !errors.Is(closeErr, net.ErrClosed) {
		err = closeErr
	}
	if cleanupErr := p.cleanup(); err == nil {
		err = cleanupErr
	}
	return err
}

func (p *ControlPlane) Close() error {
	_ = p.server.Close()
	_ = p.listener.Close()
	return p.cleanup()
}

// cleanup removes the socket before releasing the lock so a second daemon can
// never observe an unlocked lifecycle while this one still owns the path.
func (p *ControlPlane) cleanup() error {
	p.cleanupOnce.Do(func() {
		p.cleanupErr = errors.Join(removeControlSocket(p.socket), releaseControlLifecycleLock(p.lock))
	})
	return p.cleanupErr
}

func prepareControlSocket(socket string) error {
	if socket == "" || !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return errors.New("trusted control socket path is invalid")
	}
	info, err := os.Lstat(socket)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect trusted control socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("trusted control socket path already exists and is not a socket")
	}
	connection, err := net.DialTimeout("unix", socket, 100*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		return errors.New("trusted control socket is already active")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("refuse unsafe trusted control socket cleanup: %w", err)
	}
	return removeControlSocket(socket)
}

func removeControlSocket(socket string) error {
	info, err := os.Lstat(socket)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refuse to remove non-socket trusted control path")
	}
	return os.Remove(socket)
}

type ControlServer struct {
	service  *ActionService
	reviewer string
	mux      *http.ServeMux
}

func NewControlServer(service *ActionService) *ControlServer {
	// The account is derived by the daemon, never supplied by a socket caller.
	reviewer := fmt.Sprintf("local-unix-uid-%d", os.Geteuid())
	server := &ControlServer{service: service, reviewer: reviewer, mux: http.NewServeMux()}
	server.mux.HandleFunc("/v1/requests", server.requests)
	server.mux.HandleFunc("/v1/requests/", server.request)
	return server
}

func (s *ControlServer) Handler() http.Handler { return trustedSecurityHeaders(s.mux) }

func (s *ControlServer) requests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		controlMethodNotAllowed(w, http.MethodGet)
		return
	}
	if !controlNoBody(r) {
		controlError(w, http.StatusBadRequest, "request body is not allowed")
		return
	}
	cursor, ok := controlPageQuery(r)
	if !ok {
		controlError(w, http.StatusBadRequest, "invalid request page")
		return
	}
	records, next, err := s.service.ControlRecordPage(cursor)
	if err != nil {
		controlError(w, http.StatusBadRequest, "invalid request page")
		return
	}
	response := ControlPage{Requests: make([]ControlRecord, 0, len(records)), NextCursor: next}
	for _, record := range records {
		response.Requests = append(response.Requests, s.sanitize(record))
	}
	controlWrite(w, http.StatusOK, response)
}

func (s *ControlServer) request(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/requests/"), "/")
	if !validControlRequestID(parts[0]) {
		controlError(w, http.StatusBadRequest, "invalid request id")
		return
	}
	id := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet || !controlNoQuery(r) || !controlNoBody(r) {
			if r.Method != http.MethodGet {
				controlMethodNotAllowed(w, http.MethodGet)
			} else if !controlNoBody(r) {
				controlError(w, http.StatusBadRequest, "request body is not allowed")
			} else {
				controlError(w, http.StatusBadRequest, "query parameters are not allowed")
			}
			return
		}
		record, _, found := s.service.Record(id)
		if !found {
			controlError(w, http.StatusNotFound, "request not found")
			return
		}
		controlWrite(w, http.StatusOK, s.sanitize(record))
		return
	}
	if len(parts) != 2 || (parts[1] != "execute" && parts[1] != "deny") {
		controlError(w, http.StatusNotFound, "control route not found")
		return
	}
	if r.Method != http.MethodPost {
		controlMethodNotAllowed(w, http.MethodPost)
		return
	}
	if !controlNoQuery(r) {
		controlError(w, http.StatusBadRequest, "query parameters are not allowed")
		return
	}
	planDigest, confirmed, ok := controlJSONBody(w, r, parts[1] == "execute")
	if !ok {
		return
	}
	if parts[1] == "deny" {
		if err := s.service.Deny(id, s.reviewer); err != nil {
			controlError(w, http.StatusUnprocessableEntity, "decision rejected")
			return
		}
		record, _, found := s.service.Record(id)
		if !found {
			controlError(w, http.StatusInternalServerError, "trusted state unavailable")
			return
		}
		controlWrite(w, http.StatusOK, ControlAction{Request: s.sanitize(record), Outcome: "denied"})
		return
	}
	err := s.service.Execute(r.Context(), id, s.reviewer, planDigest, confirmed)
	record, _, found := s.service.Record(id)
	if !found {
		controlError(w, http.StatusUnprocessableEntity, "execution rejected")
		return
	}
	if errors.Is(err, ErrExecutionActive) || errors.Is(err, ErrExecutionRejected) || errors.Is(err, ErrExecutionUnavailable) {
		controlWrite(w, http.StatusOK, ControlAction{Request: s.sanitize(record), Outcome: record.State})
		return
	}
	if err != nil && !errors.Is(err, ErrExecutionFailed) && !errors.Is(err, ErrExecutionUncertain) {
		controlError(w, http.StatusInternalServerError, "trusted execution state unavailable")
		return
	}
	controlWrite(w, http.StatusOK, ControlAction{Request: s.sanitize(record), Outcome: record.State})
}

func controlNoQuery(r *http.Request) bool {
	return len(r.URL.RawQuery) <= maxControlQueryBytes && r.URL.RawQuery == ""
}

func controlPageQuery(r *http.Request) (string, bool) {
	if len(r.URL.RawQuery) > maxControlQueryBytes {
		return "", false
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", false
	}
	for key, values := range query {
		if key != "cursor" || len(values) != 1 {
			return "", false
		}
	}
	cursor := query.Get("cursor")
	return cursor, paging.ValidCursor(cursor)
}

func controlNoBody(r *http.Request) bool { return r.ContentLength == 0 }

func controlJSONBody(w http.ResponseWriter, r *http.Request, requirePlan bool) (string, bool, bool) {
	if r.ContentLength < 0 || r.ContentLength > maxControlBodyBytes {
		controlError(w, http.StatusRequestEntityTooLarge, "control request body is too large")
		return "", false, false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		controlError(w, http.StatusUnsupportedMediaType, "JSON content type required")
		return "", false, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxControlBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		controlError(w, http.StatusBadRequest, "invalid control request body")
		return "", false, false
	}
	var body struct {
		PlanDigest           string `json:"plan_digest"`
		ConfirmFullAuthority bool   `json:"confirm_full_authority"`
	}
	if err := jsonstrict.DecodeOne(raw, &body); err != nil {
		controlError(w, http.StatusBadRequest, "invalid control request body")
		return "", false, false
	}
	if (requirePlan && (len(body.PlanDigest) != 64 || !body.ConfirmFullAuthority)) || (!requirePlan && (body.PlanDigest != "" || body.ConfirmFullAuthority)) {
		controlError(w, http.StatusBadRequest, "invalid control request body")
		return "", false, false
	}
	return body.PlanDigest, body.ConfirmFullAuthority, true
}

func validControlRequestID(id string) bool {
	if len(id) < 24 || len(id) > 84 || !strings.HasPrefix(id, "req_") || strings.ContainsAny(id, "/\\\r\n\x00") {
		return false
	}
	for _, character := range id {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

type ControlRequest struct {
	ID             string            `json:"id"`
	ProfileID      string            `json:"profile_id,omitempty"`
	ProfileVersion string            `json:"profile_version,omitempty"`
	Argv           []string          `json:"argv,omitempty"`
	CapabilityID   string            `json:"capability_id,omitempty"`
	Action         string            `json:"action,omitempty"`
	Arguments      map[string]string `json:"arguments,omitempty"`
	Reason         string            `json:"reason"`
	Digest         string            `json:"digest"`
	CreatedAt      string            `json:"created_at"`
	ExpiresAt      string            `json:"expires_at"`
}

type ControlPlan struct {
	ProfileID              string   `json:"profile_id"`
	ProfileVersion         string   `json:"profile_version"`
	RequestDigest          string   `json:"request_digest"`
	PlanDigest             string   `json:"plan_digest"`
	Executable             string   `json:"executable"`
	ExecutableSHA256       string   `json:"executable_sha256"`
	CredentialSourceID     string   `json:"credential_source_id"`
	SandboxLauncher        string   `json:"sandbox_launcher"`
	SandboxLauncherSHA256  string   `json:"sandbox_launcher_sha256"`
	Argv                   []string `json:"argv"`
	EscapedDisplay         string   `json:"escaped_display,omitempty"`
	CredentialAuthority    string   `json:"credential_authority"`
	ExecutionIdentity      string   `json:"execution_identity"`
	SandboxPolicy          string   `json:"sandbox_policy"`
	NetworkPolicy          string   `json:"network_policy"`
	WorkingDirectoryPolicy string   `json:"working_directory_policy"`
	TimeoutMilliseconds    int64    `json:"timeout_milliseconds"`
	OutputPolicy           string   `json:"output_policy"`
	EnvironmentPolicy      []string `json:"environment_policy"`
	ProfileConfigVersion   string   `json:"profile_config_version"`
	RiskWarnings           []string `json:"risk_warnings"`
}

type ControlRecord struct {
	Request  ControlRequest   `json:"request"`
	State    string           `json:"state"`
	Plan     *ControlPlan     `json:"plan,omitempty"`
	Attempts []ControlAttempt `json:"attempts,omitempty"`
	Receipts []Delivery       `json:"receipts,omitempty"`
}

// ControlAttempt carries the persisted, digest-verified immutable plan for
// its own history entry. ControlRecord.Plan is the current actionable plan
// until completion, then the final approved plan.
type ControlAttempt struct {
	ID             string                `json:"id"`
	RequestDigest  string                `json:"request_digest"`
	Reviewer       string                `json:"reviewer"`
	AdapterVersion string                `json:"adapter_version,omitempty"`
	ProfileID      string                `json:"profile_id,omitempty"`
	ProfileVersion string                `json:"profile_version,omitempty"`
	PlanDigest     string                `json:"plan_digest,omitempty"`
	Plan           *ControlPlan          `json:"plan,omitempty"`
	Status         string                `json:"status"`
	StartedAt      string                `json:"started_at"`
	FinishedAt     string                `json:"finished_at,omitempty"`
	FailureCode    string                `json:"failure_code,omitempty"`
	OutputPreview  *ControlOutputPreview `json:"output_preview,omitempty"`
}

// ControlOutputPreview is visible only through the same-UID trusted control
// socket. It is copied only after storage has bounded, escaped, and redacted
// it; requester, receipt, MCP, and Hermes projections deliberately omit it.
type ControlOutputPreview struct {
	LocalOnly       bool   `json:"local_only"`
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	Redacted        bool   `json:"redacted,omitempty"`
}

type ControlPage struct {
	Requests   []ControlRecord `json:"requests"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

type ControlAction struct {
	Request ControlRecord `json:"request"`
	Outcome string        `json:"outcome"`
}

func (s *ControlServer) sanitize(record Record) ControlRecord {
	result := ControlRecord{
		Request: ControlRequest{ID: record.Request.ID, ProfileID: record.Request.ProfileID, ProfileVersion: record.Request.ProfileVersion,
			Argv: append([]string(nil), record.Request.Argv...), CapabilityID: record.Request.CapabilityID, Action: record.Request.Action,
			Arguments: cloneStringMap(record.Request.Arguments), Reason: record.Request.Reason, Digest: record.Request.Digest, CreatedAt: record.Request.CreatedAt, ExpiresAt: record.Request.ExpiresAt},
		State: record.State, Attempts: make([]ControlAttempt, 0, len(record.Attempts)), Receipts: append([]Delivery(nil), record.Receipts...),
	}
	for _, attempt := range record.Attempts {
		var plan *ControlPlan
		if attempt.Plan != nil && verifyExecutionPlanDigest(*attempt.Plan) == nil && attempt.PlanDigest == attempt.Plan.Digest {
			plan = controlPlan(*attempt.Plan, false)
		}
		result.Attempts = append(result.Attempts, ControlAttempt{
			ID: attempt.ID, RequestDigest: attempt.RequestDigest, Reviewer: attempt.Reviewer,
			AdapterVersion: attempt.AdapterVersion, ProfileID: attempt.ProfileID, ProfileVersion: attempt.ProfileVersion,
			PlanDigest: attempt.PlanDigest, Plan: plan, Status: attempt.Status, StartedAt: attempt.StartedAt,
			FinishedAt: attempt.FinishedAt, FailureCode: attempt.FailureCode, OutputPreview: controlOutputPreview(attempt.OutputPreview),
		})
	}
	var plan *ExecutionPlan
	if record.State == attemptStatusRunning || record.State == model.DecisionExecuted {
		plan, _ = persistedExecutionPlan(record)
	} else {
		if current, err := resolveExecutionPlan(record.Request, s.service.store.capabilities, s.service.store.now().UTC(), s.service.store.requestMaxTTL, s.service.store.execution); err == nil {
			plan = &current
		}
	}
	if plan != nil {
		result.Plan = controlPlan(*plan, true)
	}
	return result
}

func controlPlan(plan ExecutionPlan, includeDisplay bool) *ControlPlan {
	display := ""
	if includeDisplay {
		display = escapedCommand(plan)
	}
	return &ControlPlan{ProfileID: plan.ProfileID, ProfileVersion: plan.ProfileVersion, RequestDigest: plan.RequestDigest,
		PlanDigest: plan.Digest, Executable: plan.Executable, ExecutableSHA256: plan.ExecutableSHA256,
		CredentialSourceID: plan.CredentialSourceID, SandboxLauncher: plan.SandboxLauncher, SandboxLauncherSHA256: plan.SandboxLauncherSHA256,
		Argv: append([]string(nil), plan.Argv...), EscapedDisplay: display, CredentialAuthority: plan.CredentialAuthority,
		ExecutionIdentity: plan.ExecutionIdentity, SandboxPolicy: plan.SandboxPolicy, NetworkPolicy: plan.NetworkPolicy,
		WorkingDirectoryPolicy: plan.WorkingDirectoryPolicy, TimeoutMilliseconds: plan.TimeoutMilliseconds,
		OutputPolicy: plan.OutputPolicy, EnvironmentPolicy: append([]string(nil), plan.EnvironmentPolicy...),
		ProfileConfigVersion: plan.ProfileConfigVersion, RiskWarnings: classifyGitHubRisk(plan.Argv)}
}

func controlOutputPreview(preview *ExecutionOutputPreview) *ControlOutputPreview {
	if preview == nil {
		return nil
	}
	return &ControlOutputPreview{LocalOnly: true, Stdout: preview.Stdout, Stderr: preview.Stderr,
		StdoutTruncated: preview.StdoutTruncated, StderrTruncated: preview.StderrTruncated, Redacted: preview.Redacted}
}

func cloneStringMap(source map[string]string) map[string]string {
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func controlWrite(w http.ResponseWriter, status int, value any) {
	encoded, err := httpjson.Marshal(value)
	if err != nil || len(encoded) > maxControlJSONBytes {
		status = http.StatusInternalServerError
		encoded = []byte(`{"error":"trusted control response exceeds size limit"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

func controlError(w http.ResponseWriter, status int, message string) {
	controlWrite(w, status, map[string]string{"error": message})
}

func controlMethodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	controlError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// ControlClient talks only to a running daemon. It never opens trusted state,
// loads a signing key, or invokes a provider executable.
type ControlClient struct {
	client *http.Client
}

func NewControlClient(socket string) (*ControlClient, error) {
	if socket == "" || !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return nil, errors.New("trusted control socket path is invalid")
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		DisableCompression: true,
		DisableKeepAlives:  true,
	}
	return &ControlClient{client: &http.Client{
		// execution_timeout is capped at five minutes; retain a small response
		// margin so the CLI does not cancel a valid daemon-owned execution.
		Transport: transport, Timeout: maxControlCallTime,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (c *ControlClient) List(ctx context.Context, cursor string) (ControlPage, error) {
	var page ControlPage
	if !paging.ValidCursor(cursor) {
		return page, errors.New("trusted control cursor is invalid")
	}
	path := "/v1/requests"
	if cursor != "" {
		path += "?cursor=" + url.QueryEscape(cursor)
	}
	return page, c.do(ctx, http.MethodGet, path, nil, &page)
}

func (c *ControlClient) Show(ctx context.Context, id string) (ControlRecord, error) {
	var record ControlRecord
	if !validControlRequestID(id) {
		return record, errors.New("trusted control request is invalid")
	}
	return record, c.do(ctx, http.MethodGet, "/v1/requests/"+id, nil, &record)
}

func (c *ControlClient) Execute(ctx context.Context, id, planDigest string, confirmFullAuthority bool) (ControlAction, error) {
	if len(planDigest) != 64 {
		return ControlAction{}, errors.New("trusted resolved plan digest is invalid")
	}
	if !confirmFullAuthority {
		return ControlAction{}, ErrExecutionConfirmationRequired
	}
	return c.action(ctx, id, "execute", planDigest, true)
}

func (c *ControlClient) Deny(ctx context.Context, id string) (ControlAction, error) {
	return c.action(ctx, id, "deny", "", false)
}

func (c *ControlClient) action(ctx context.Context, id, action, planDigest string, confirmFullAuthority bool) (ControlAction, error) {
	var result ControlAction
	if !validControlRequestID(id) {
		return result, errors.New("trusted control request is invalid")
	}
	body := []byte("{}")
	if planDigest != "" {
		body, _ = httpjson.Marshal(map[string]any{"plan_digest": planDigest, "confirm_full_authority": confirmFullAuthority})
	}
	return result, c.do(ctx, http.MethodPost, "/v1/requests/"+id+"/"+action, bytes.NewReader(body), &result)
}

func (c *ControlClient) do(ctx context.Context, method, path string, body io.Reader, target any) error {
	request, err := http.NewRequestWithContext(ctx, method, "http://airlock-control.invalid"+path, body)
	if err != nil {
		return errors.New("trusted control request is invalid")
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return errors.New("trusted daemon is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return errors.New("trusted daemon rejected the control request")
	}
	if mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		return errors.New("trusted daemon returned an invalid control response")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxControlJSONBytes+1))
	if err != nil || len(raw) > maxControlJSONBytes {
		return errors.New("trusted daemon returned an invalid control response")
	}
	if err := jsonstrict.DecodeOne(raw, target); err != nil {
		return errors.New("trusted daemon returned an invalid control response")
	}
	return nil
}
