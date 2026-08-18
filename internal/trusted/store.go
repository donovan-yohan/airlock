package trusted

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/donovan-yohan/airlock/internal/config"
	"github.com/donovan-yohan/airlock/internal/model"
	"github.com/donovan-yohan/airlock/internal/paging"
	"github.com/donovan-yohan/airlock/internal/statefile"
)

const (
	// Request/receipt/attempt field bounds plus these caps keep a fully written
	// trusted state below statefile's shared 16 MiB atomic limit with room for
	// format overhead. The bound is proved with maximal literal escapable data.
	maxTrustedRequests     = 28
	maxExecutionAttempts   = 4
	maxReceiptsPerRecord   = maxExecutionAttempts + 1
	maxExecutionPathBytes  = 1024
	attemptStatusRunning   = "running"
	attemptStatusFailed    = "failed"
	attemptStatusUncertain = "uncertain"
	attemptStatusSucceeded = "succeeded"
)

var (
	ErrExecutionUnavailable          = errors.New("trusted execution is not configured")
	ErrExecutionActive               = errors.New("an execution attempt is already running")
	ErrExecutionRejected             = errors.New("execution is not allowed for this request state")
	ErrExecutionConfirmationRequired = errors.New("explicit full-authority confirmation is required")
	ErrExecutionFailed               = errors.New("trusted provider invocation failed")
	ErrExecutionUncertain            = errors.New("provider outcome is uncertain; verify or explicitly retry")
)

// ExecutionConfig originates exclusively from strict trusted-node config. The
// requester never receives it. Review derives a plan; approval persists that
// exact plan, and the runner consumes the persisted reservation.
type ExecutionConfig struct {
	GitHubCLIPath        string
	GitHubConfigDir      string
	SandboxCLIPath       string
	Timeout              time.Duration
	Profile              model.CommandProfile
	ProfileConfigVersion string
	ExecutionIdentity    string
	// ExecutableSHA256 is populated by NewStore from the executable file. Tests
	// with an injected non-process runner may supply a synthetic lowercase digest.
	ExecutableSHA256   string
	SandboxCLISHA256   string
	CredentialSourceID string
	// sandboxLauncherDigestForTest is intentionally unexported: rootless test
	// images may expose trusted OS files as UID 65534, but a decoded trusted
	// config can never bypass the production UID 0 launcher verification.
	sandboxLauncherDigestForTest string
}

// ExecutionAttempt is bounded trusted-local audit state. Its optional preview
// is already sanitized/redacted and is never placed in receipts or requester
// synchronization; environment, provider response, and free-form command
// fields remain absent.
type ExecutionAttempt struct {
	ID             string                  `json:"id"`
	RequestDigest  string                  `json:"request_digest"`
	Reviewer       string                  `json:"reviewer"`
	AdapterVersion string                  `json:"adapter_version,omitempty"`
	ProfileID      string                  `json:"profile_id,omitempty"`
	ProfileVersion string                  `json:"profile_version,omitempty"`
	PlanDigest     string                  `json:"plan_digest,omitempty"`
	Plan           *ExecutionPlan          `json:"plan,omitempty"`
	Status         string                  `json:"status"`
	StartedAt      string                  `json:"started_at"`
	FinishedAt     string                  `json:"finished_at,omitempty"`
	FailureCode    string                  `json:"failure_code,omitempty"`
	OutputPreview  *ExecutionOutputPreview `json:"output_preview,omitempty"`
}

type Delivery struct {
	Receipt   model.Receipt `json:"receipt"`
	Delivered bool          `json:"delivered"`
}

type Record struct {
	Request  model.Request      `json:"request"`
	State    string             `json:"state"`
	Receipts []Delivery         `json:"receipts"`
	Attempts []ExecutionAttempt `json:"attempts,omitempty"`
}

type persistedState struct {
	Requests map[string]Record `json:"requests"`
}

type executionRunner interface {
	Run(context.Context, ExecutionPlan, []string) (ExecutionOutputPreview, error)
}

type directExecutionRunner struct{}

func (directExecutionRunner) Run(ctx context.Context, plan ExecutionPlan, environment []string) (ExecutionOutputPreview, error) {
	return runDirectCommand(ctx, plan, environment)
}

func minimalChildEnvironment() []string {
	// The child receives a complete fixed environment. In particular neither
	// inherited token/proxy variables nor the operator's HOME are propagated.
	return []string{
		"GH_CONFIG_DIR=/airlock/home/.config/gh",
		"GH_PROMPT_DISABLED=1",
		"GH_NO_UPDATE_NOTIFIER=1",
		"NO_COLOR=1",
		"TERM=dumb",
		"HOME=/airlock/home",
		"LC_ALL=C",
		"PATH=/airlock/bin",
		"XDG_CONFIG_HOME=/airlock/home/.config",
		"XDG_DATA_HOME=/airlock/home/.local",
		"XDG_CACHE_HOME=/airlock/home/.cache",
	}
}

func (s *Store) prepareInvocation(attemptID string, plan *ExecutionPlan) ([]string, func(), error) {
	if s.execution == nil || s.executionRoot == "" || !strings.HasPrefix(attemptID, "att_") {
		return nil, func() {}, errors.New("execution isolation is unavailable")
	}
	root := filepath.Join(s.executionRoot, attemptID)
	if filepath.Dir(root) != s.executionRoot {
		return nil, func() {}, errors.New("invalid invocation path")
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	if err := os.Mkdir(root, 0o700); err != nil {
		return nil, cleanup, err
	}
	configDir := filepath.Join(root, "gh-config")
	workDir := filepath.Join(root, "work")
	binDir := filepath.Join(root, "bin")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	if err := os.Mkdir(workDir, 0o700); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	if err := os.Mkdir(binDir, 0o700); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	credentialID, err := snapshotHostsYAML(s.execution.GitHubConfigDir, filepath.Join(configDir, "hosts.yml"))
	if err != nil || credentialID != plan.CredentialSourceID {
		cleanup()
		return nil, func() {}, errors.New("GitHub authentication source changed")
	}
	// Injected runners are used only by in-process tests. They never invoke a
	// provider and retain the real hosts.yml snapshot/drift check while avoiding
	// a fabricated filesystem executable requirement.
	if !s.verifyExecutable {
		plan.runtimeWorkingDirectory = workDir
		plan.runtimeExecutable = filepath.Join(binDir, "gh")
		plan.runtimeSandboxLauncher = s.execution.SandboxCLIPath
		return minimalChildEnvironment(), cleanup, nil
	}
	executableID, err := snapshotTrustedFile(s.execution.GitHubCLIPath, filepath.Join(binDir, "gh"), "airlock-executable/v1", maxExecutableBytes, true, false)
	if err != nil || executableID != plan.ExecutableSHA256 {
		cleanup()
		return nil, func() {}, errors.New("trusted executable changed")
	}
	plan.runtimeWorkingDirectory = workDir
	plan.runtimeExecutable = filepath.Join(binDir, "gh")
	plan.runtimeSandboxLauncher = s.execution.SandboxCLIPath
	return minimalChildEnvironment(), cleanup, nil
}

func cleanupInvocationRoot(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "att_") {
			return errors.New("unexpected entry in invocation directory")
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

type Store struct {
	mu               sync.RWMutex
	path             string
	privateKey       ed25519.PrivateKey
	capabilities     []config.TrustedCapability
	requestMaxTTL    time.Duration
	receiptTTL       time.Duration
	execution        *ExecutionConfig
	executionRoot    string
	verifyExecutable bool
	runner           executionRunner
	save             func(string, any) error
	now              func() time.Time
	state            persistedState
}

// NewStore keeps its optional execution argument so old durable-state readers
// can still be constructed for recovery tests. A serving trusted node always
// supplies exactly one validated execution configuration.
func NewStore(stateDir string, privateKey ed25519.PrivateKey, capabilities []config.TrustedCapability, requestMaxTTL, receiptTTL time.Duration, execution ...ExecutionConfig) (*Store, error) {
	if len(execution) > 1 {
		return nil, errors.New("multiple trusted execution configurations")
	}
	store := &Store{
		path: filepath.Join(stateDir, "trusted-state.json"), privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		capabilities: append([]config.TrustedCapability(nil), capabilities...), requestMaxTTL: requestMaxTTL,
		receiptTTL: receiptTTL, now: time.Now, state: persistedState{Requests: map[string]Record{}}, runner: directExecutionRunner{}, save: statefile.Save,
	}
	if len(execution) == 1 {
		normalized, verifyExecutable, err := normalizeExecutionConfig(execution[0])
		if err != nil {
			return nil, err
		}
		if err := statefile.EnsurePrivateDir(normalized.GitHubConfigDir); err != nil {
			return nil, fmt.Errorf("prepare GitHub config directory: %w", err)
		}
		store.execution = &normalized
		store.verifyExecutable = verifyExecutable
		store.executionRoot = filepath.Join(stateDir, "invocations")
		if err := statefile.EnsurePrivateDir(store.executionRoot); err != nil {
			return nil, fmt.Errorf("prepare invocation directory: %w", err)
		}
		if err := cleanupInvocationRoot(store.executionRoot); err != nil {
			return nil, fmt.Errorf("clean recovered invocation state: %w", err)
		}
	}
	if err := statefile.Load(store.path, &store.state); err != nil {
		return nil, err
	}
	if store.state.Requests == nil {
		store.state.Requests = map[string]Record{}
	}
	// Do not turn a bad durable record into a delete-and-rewrite operation.
	// Complete validation uses only stable protocol envelopes and persisted plan
	// integrity; current policy is consulted later only for new work/actions.
	if err := store.validateLoaded(); err != nil {
		return nil, errors.New("persisted trusted state is invalid")
	}
	changed := false
	for id, record := range store.state.Requests {
		if record.State != attemptStatusRunning || len(record.Attempts) == 0 {
			continue
		}
		record = cloneRecord(record)
		last := len(record.Attempts) - 1
		// A process stopped between reservation and completion might have made
		// the provider call. Recovery must preserve that ambiguity.
		record.Attempts[last].Status = attemptStatusUncertain
		record.Attempts[last].FailureCode = "interrupted"
		record.Attempts[last].FinishedAt = model.Timestamp(monotonicRecordTime(record, store.now().UTC()))
		record.State = attemptStatusUncertain
		store.state.Requests[id] = record
		changed = true
	}
	prune := store.expiredIDs(store.now().UTC())
	for _, id := range prune {
		delete(store.state.Requests, id)
	}
	if changed || len(prune) != 0 {
		if err := store.commit(store.state); err != nil {
			return nil, fmt.Errorf("persist recovered trusted state: %w", err)
		}
	}
	return store, nil
}

func validateExecutionConfig(value ExecutionConfig) error {
	for name, path := range map[string]string{"github cli path": value.GitHubCLIPath, "GitHub config directory": value.GitHubConfigDir, "sandbox cli path": value.SandboxCLIPath} {
		if !validExecutionPath(path) {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if value.Timeout < time.Second || value.Timeout > 5*time.Minute {
		return errors.New("trusted execution timeout is outside bounds")
	}
	if err := model.ValidateCommandProfile(value.Profile); err != nil {
		return fmt.Errorf("invalid command profile: %w", err)
	}
	if value.ProfileConfigVersion == "" || len(value.ProfileConfigVersion) > 64 || !safeAttemptText(value.ProfileConfigVersion, 64) {
		return errors.New("invalid profile config version")
	}
	if value.ExecutionIdentity == "" || len(value.ExecutionIdentity) > 200 || !safeAttemptText(value.ExecutionIdentity, 200) {
		return errors.New("invalid execution identity")
	}
	if value.CredentialSourceID != "" && !validTrustedDigest(value.CredentialSourceID) {
		return errors.New("invalid credential source identity")
	}
	return nil
}

func normalizeExecutionConfig(value ExecutionConfig) (ExecutionConfig, bool, error) {
	if err := validateExecutionConfig(value); err != nil {
		return ExecutionConfig{}, false, err
	}
	if value.sandboxLauncherDigestForTest != "" {
		if !validTrustedDigest(value.sandboxLauncherDigestForTest) {
			return ExecutionConfig{}, false, errors.New("invalid test sandbox launcher digest")
		}
		value.SandboxCLISHA256 = value.sandboxLauncherDigestForTest
	} else {
		launcherDigest, err := computeRootOwnedExecutableSHA256(value.SandboxCLIPath)
		if err != nil {
			return ExecutionConfig{}, false, fmt.Errorf("validate sandbox launcher: %w", err)
		}
		value.SandboxCLISHA256 = launcherDigest
	}
	// Authentication-source identity is an environment-dependent prerequisite,
	// never a property of a persisted request. Resolve it before state loading so
	// a missing/non-private hosts.yml cannot cause a recovery rewrite.
	credentialID, err := credentialSourceIdentity(value.GitHubConfigDir)
	if err != nil {
		return ExecutionConfig{}, false, fmt.Errorf("validate GitHub authentication source: %w", err)
	}
	if value.CredentialSourceID != "" && value.CredentialSourceID != credentialID {
		return ExecutionConfig{}, false, errors.New("configured credential source identity changed")
	}
	value.CredentialSourceID = credentialID
	if value.ExecutableSHA256 != "" {
		if !validTrustedDigest(value.ExecutableSHA256) {
			return ExecutionConfig{}, false, errors.New("invalid trusted executable digest")
		}
		return value, false, nil
	}
	digest, err := computeExecutableSHA256(value.GitHubCLIPath)
	if err != nil {
		return ExecutionConfig{}, false, err
	}
	value.ExecutableSHA256 = digest
	return value, true, nil
}

func validTrustedDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validExecutionPath(path string) bool {
	if path == "" || len(path) > maxExecutionPathBytes || !utf8.ValidString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return false
	}
	for _, character := range path {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) || isExecutionPathNoncharacter(character) {
			return false
		}
	}
	return true
}

func isExecutionPathNoncharacter(character rune) bool {
	return character >= 0xfdd0 && character <= 0xfdef || character <= utf8.MaxRune && character&0xfffe == 0xfffe
}

func (s *Store) Ingest(request model.Request) error {
	now := s.now().UTC()
	if _, err := resolveExecutionPlan(request, s.capabilities, now, s.requestMaxTTL, s.execution); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if existing, found := s.state.Requests[request.ID]; found {
		if existing.Request.Digest != request.Digest {
			return errors.New("request id mutation refused")
		}
		return nil
	}
	if len(s.state.Requests) >= maxTrustedRequests {
		return errors.New("trusted request store is full")
	}
	record := Record{Request: cloneRequest(request), State: "pending", Receipts: []Delivery{}, Attempts: []ExecutionAttempt{}}
	next := clonePersistedState(s.state)
	next.Requests[request.ID] = record
	return s.commit(next)
}

func (s *Store) Execute(ctx context.Context, id, reviewer, expectedPlanDigest string) error {
	plan, attemptID, err := s.planForStaging(id, expectedPlanDigest)
	if err != nil {
		return err
	}
	environment, cleanup, err := s.prepareInvocation(attemptID, &plan)
	if err != nil {
		cleanup()
		return ErrExecutionFailed
	}
	defer cleanup()
	deadline, err := s.reservePreparedExecution(id, reviewer, expectedPlanDigest, plan, attemptID)
	if err != nil {
		return err
	}
	// Reservation commit above occurs while locked. Provider work intentionally
	// happens after releasing it, so sync and reviewers cannot deadlock behind
	// a slow process.
	executionContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := verifyExecutionPlanDigest(plan); err != nil {
		_ = s.completeAttempt(id, attemptID, attemptStatusFailed, "plan_tampered")
		return ErrExecutionFailed
	}
	preview, err := s.runner.Run(executionContext, plan, environment)
	return s.completeExecution(id, attemptID, preview, err, executionContext.Err())
}

// planForStaging checks the review-time plan, then creates the private attempt
// snapshot before any durable approval/running reservation. Failed staging is
// therefore non-execution and leaves no misleading admission receipt.
func (s *Store) planForStaging(id, expectedPlanDigest string) (ExecutionPlan, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	s.sweepLocked(now)
	if s.execution == nil {
		return ExecutionPlan{}, "", ErrExecutionUnavailable
	}
	record, found := s.state.Requests[id]
	if !found {
		return ExecutionPlan{}, "", ErrExecutionRejected
	}
	if record.State == attemptStatusRunning {
		return ExecutionPlan{}, "", ErrExecutionActive
	}
	if (record.State != "pending" && record.State != attemptStatusFailed && record.State != attemptStatusUncertain) || len(record.Attempts) >= maxExecutionAttempts || len(record.Receipts) >= maxReceiptsPerRecord {
		return ExecutionPlan{}, "", ErrExecutionRejected
	}
	plan, err := resolveExecutionPlan(record.Request, s.capabilities, now, s.requestMaxTTL, s.execution)
	if err != nil || expectedPlanDigest == "" || expectedPlanDigest != plan.Digest {
		return ExecutionPlan{}, "", ErrExecutionRejected
	}
	attemptID, err := model.NewRandom("att_", 18)
	if err != nil {
		return ExecutionPlan{}, "", err
	}
	return plan, attemptID, nil
}

func (s *Store) reserveExecution(id, reviewer, expectedPlanDigest string) (ExecutionPlan, string, time.Time, error) {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if s.execution == nil {
		return ExecutionPlan{}, "", time.Time{}, ErrExecutionUnavailable
	}
	record, found := s.state.Requests[id]
	if !found {
		return ExecutionPlan{}, "", time.Time{}, ErrExecutionRejected
	}
	if record.State == attemptStatusRunning {
		return ExecutionPlan{}, "", time.Time{}, ErrExecutionActive
	}
	if record.State != "pending" && record.State != attemptStatusFailed && record.State != attemptStatusUncertain {
		return ExecutionPlan{}, "", time.Time{}, ErrExecutionRejected
	}
	if len(record.Attempts) >= maxExecutionAttempts || len(record.Receipts) >= maxReceiptsPerRecord {
		return ExecutionPlan{}, "", time.Time{}, ErrExecutionRejected
	}
	plan, err := resolveExecutionPlan(record.Request, s.capabilities, now, s.requestMaxTTL, s.execution)
	if err != nil {
		return ExecutionPlan{}, "", time.Time{}, ErrExecutionRejected
	}
	if expectedPlanDigest == "" || expectedPlanDigest != plan.Digest {
		return ExecutionPlan{}, "", time.Time{}, ErrExecutionRejected
	}
	expires, _ := time.Parse(time.RFC3339, record.Request.ExpiresAt)
	deadline := now.Add(s.execution.Timeout)
	if expires.Before(deadline) {
		deadline = expires
	}
	if !deadline.After(now) {
		return ExecutionPlan{}, "", time.Time{}, ErrExecutionRejected
	}
	eventTime := monotonicRecordTime(record, now)
	approval, err := s.newReceipt(record.Request, model.DecisionApproveForExecution, reviewer, plan, eventTime)
	if err != nil {
		return ExecutionPlan{}, "", time.Time{}, err
	}
	attemptID, err := model.NewRandom("att_", 18)
	if err != nil {
		return ExecutionPlan{}, "", time.Time{}, err
	}
	record = cloneRecord(record)
	record.State = attemptStatusRunning
	record.Receipts = append(record.Receipts, Delivery{Receipt: approval})
	record.Attempts = append(record.Attempts, ExecutionAttempt{
		ID: attemptID, RequestDigest: record.Request.Digest, Reviewer: reviewer, AdapterVersion: plan.LegacyAdapter,
		ProfileID: plan.ProfileID, ProfileVersion: plan.ProfileVersion, PlanDigest: plan.Digest, Plan: cloneExecutionPlan(&plan),
		Status: attemptStatusRunning, StartedAt: model.Timestamp(eventTime),
	})
	next := clonePersistedState(s.state)
	next.Requests[id] = record
	if err := s.commit(next); err != nil {
		return ExecutionPlan{}, "", time.Time{}, err
	}
	return plan, attemptID, deadline, nil
}

func (s *Store) reservePreparedExecution(id, reviewer, expectedPlanDigest string, staged ExecutionPlan, attemptID string) (time.Time, error) {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if s.execution == nil {
		return time.Time{}, ErrExecutionUnavailable
	}
	record, found := s.state.Requests[id]
	if !found || record.State == attemptStatusRunning || (record.State != "pending" && record.State != attemptStatusFailed && record.State != attemptStatusUncertain) || len(record.Attempts) >= maxExecutionAttempts || len(record.Receipts) >= maxReceiptsPerRecord {
		return time.Time{}, ErrExecutionRejected
	}
	current, err := resolveExecutionPlan(record.Request, s.capabilities, now, s.requestMaxTTL, s.execution)
	if err != nil || expectedPlanDigest == "" || expectedPlanDigest != staged.Digest || current.Digest != staged.Digest {
		return time.Time{}, ErrExecutionRejected
	}
	expires, _ := time.Parse(time.RFC3339, record.Request.ExpiresAt)
	deadline := now.Add(s.execution.Timeout)
	if expires.Before(deadline) {
		deadline = expires
	}
	if !deadline.After(now) {
		return time.Time{}, ErrExecutionRejected
	}
	// The kernel executes this canonical path directly, rather than an
	// invocation-local copy: Ubuntu's user-namespace grant can be keyed to the
	// administrator-owned launcher path. Reopen and rehash it while holding the
	// reservation lock immediately before durable admission.
	if s.verifyExecutable {
		launcherID, err := computeSandboxLauncherSHA256(s.execution.SandboxCLIPath, s.execution.sandboxLauncherDigestForTest != "")
		if err != nil || launcherID != staged.SandboxLauncherSHA256 {
			return time.Time{}, ErrExecutionRejected
		}
	}
	eventTime := monotonicRecordTime(record, now)
	approval, err := s.newReceipt(record.Request, model.DecisionApproveForExecution, reviewer, staged, eventTime)
	if err != nil {
		return time.Time{}, err
	}
	record = cloneRecord(record)
	record.State = attemptStatusRunning
	record.Receipts = append(record.Receipts, Delivery{Receipt: approval})
	record.Attempts = append(record.Attempts, ExecutionAttempt{ID: attemptID, RequestDigest: record.Request.Digest, Reviewer: reviewer, AdapterVersion: staged.LegacyAdapter, ProfileID: staged.ProfileID, ProfileVersion: staged.ProfileVersion, PlanDigest: staged.Digest, Plan: cloneExecutionPlan(&staged), Status: attemptStatusRunning, StartedAt: model.Timestamp(eventTime)})
	next := clonePersistedState(s.state)
	next.Requests[id] = record
	if err := s.commit(next); err != nil {
		return time.Time{}, err
	}
	return deadline, nil
}

func (s *Store) completeExecution(id, attemptID string, preview ExecutionOutputPreview, runErr, contextErr error) error {
	if runErr != nil || contextErr != nil {
		status, code := executionFailureOutcome(runErr, contextErr)
		if err := s.completeAttemptPreview(id, attemptID, status, code, preview); err != nil {
			return ErrExecutionUncertain
		}
		if status == attemptStatusFailed {
			return ErrExecutionFailed
		}
		return ErrExecutionUncertain
	}
	preview = sanitizeExecutionOutputPreview(preview)
	now := s.now().UTC()
	s.mu.Lock()
	record, found := s.state.Requests[id]
	if !found || record.State != attemptStatusRunning || !lastAttemptIs(record, attemptID, attemptStatusRunning) {
		s.mu.Unlock()
		return ErrExecutionUncertain
	}
	expires, _ := time.Parse(time.RFC3339, record.Request.ExpiresAt)
	if !now.Before(expires) {
		s.mu.Unlock()
		if err := s.completeAttempt(id, attemptID, attemptStatusUncertain, "expired_during_execution"); err != nil {
			return ErrExecutionUncertain
		}
		return ErrExecutionUncertain
	}
	lastAttempt := record.Attempts[len(record.Attempts)-1]
	if lastAttempt.Plan == nil || verifyExecutionPlanDigest(*lastAttempt.Plan) != nil || lastAttempt.PlanDigest != lastAttempt.Plan.Digest {
		s.mu.Unlock()
		_ = s.completeAttempt(id, attemptID, attemptStatusUncertain, "plan_tampered")
		return ErrExecutionUncertain
	}
	eventTime := monotonicRecordTime(record, now)
	receipt, err := s.newReceipt(record.Request, model.DecisionExecuted, lastAttempt.Reviewer, *lastAttempt.Plan, eventTime)
	if err != nil {
		s.mu.Unlock()
		_ = s.completeAttempt(id, attemptID, attemptStatusUncertain, "completion_persistence_failed")
		return ErrExecutionUncertain
	}
	record = cloneRecord(record)
	last := len(record.Attempts) - 1
	record.Attempts[last].Status = attemptStatusSucceeded
	record.Attempts[last].OutputPreview = cloneExecutionOutputPreview(&preview)
	record.Attempts[last].FinishedAt = model.Timestamp(eventTime)
	record.State = model.DecisionExecuted
	record.Receipts = append(record.Receipts, Delivery{Receipt: receipt})
	next := clonePersistedState(s.state)
	next.Requests[id] = record
	err = s.commit(next)
	s.mu.Unlock()
	if err == nil {
		return nil
	}
	// A child may have succeeded even though the success receipt was not made
	// durable. Never claim executed in that case; make a best-effort durable
	// uncertain result, otherwise restart recovery changes running to uncertain.
	_ = s.completeAttempt(id, attemptID, attemptStatusUncertain, "completion_persistence_failed")
	return ErrExecutionUncertain
}

func (s *Store) completeAttempt(id, attemptID, status, code string) error {
	return s.completeAttemptPreview(id, attemptID, status, code, ExecutionOutputPreview{})
}

func (s *Store) completeAttemptPreview(id, attemptID, status, code string, preview ExecutionOutputPreview) error {
	preview = sanitizeExecutionOutputPreview(preview)
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.state.Requests[id]
	if !found || !lastAttemptIs(record, attemptID, attemptStatusRunning) {
		return errors.New("attempt record unavailable")
	}
	eventTime := monotonicRecordTime(record, now)
	record = cloneRecord(record)
	last := len(record.Attempts) - 1
	record.Attempts[last].Status = status
	record.Attempts[last].FailureCode = code
	record.Attempts[last].OutputPreview = cloneExecutionOutputPreview(&preview)
	record.Attempts[last].FinishedAt = model.Timestamp(eventTime)
	record.State = status
	next := clonePersistedState(s.state)
	next.Requests[id] = record
	if err := s.commit(next); err == nil {
		return nil
	}
	// commit may have reloaded the durable pre-effect running state. Preserve
	// only the enumerated uncertainty marker if that second durable write works.
	record, found = s.state.Requests[id]
	if !found || !lastAttemptIs(record, attemptID, attemptStatusRunning) {
		return errors.New("attempt completion persistence failed")
	}
	record = cloneRecord(record)
	last = len(record.Attempts) - 1
	record.Attempts[last].Status = attemptStatusUncertain
	record.Attempts[last].FailureCode = "completion_persistence_failed"
	record.Attempts[last].FinishedAt = model.Timestamp(eventTime)
	record.State = attemptStatusUncertain
	next = clonePersistedState(s.state)
	next.Requests[id] = record
	return s.commit(next)
}

func executionFailureOutcome(runErr, contextErr error) (string, string) {
	if errors.Is(contextErr, context.DeadlineExceeded) {
		return attemptStatusUncertain, "timed_out"
	}
	if errors.Is(contextErr, context.Canceled) {
		return attemptStatusUncertain, "cancelled"
	}
	if errors.Is(runErr, os.ErrNotExist) {
		return attemptStatusFailed, "missing_executable"
	}
	var executionError *exec.Error
	if errors.As(runErr, &executionError) {
		if errors.Is(executionError.Err, os.ErrNotExist) {
			return attemptStatusFailed, "missing_executable"
		}
		return attemptStatusFailed, "start_failed"
	}
	// A generic exit result cannot prove whether GitHub accepted the mutation.
	return attemptStatusUncertain, "nonzero_exit"
}

func lastAttemptIs(record Record, id, status string) bool {
	return len(record.Attempts) != 0 && record.Attempts[len(record.Attempts)-1].ID == id && record.Attempts[len(record.Attempts)-1].Status == status
}

// monotonicRecordTime keeps self-written durable event timestamps ordered even
// if the host wall clock steps backwards. Loaded/admitted records already have
// validated RFC3339 timestamps, so parse failures simply leave the current
// floor unchanged and are still caught by the durable-state validator.
func monotonicRecordTime(record Record, now time.Time) time.Time {
	floor := time.Time{}
	advance := func(value string) {
		if parsed, err := time.Parse(time.RFC3339, value); err == nil && parsed.After(floor) {
			floor = parsed
		}
	}
	advance(record.Request.CreatedAt)
	for _, delivery := range record.Receipts {
		advance(delivery.Receipt.CreatedAt)
	}
	for _, attempt := range record.Attempts {
		advance(attempt.StartedAt)
		if attempt.FinishedAt != "" {
			advance(attempt.FinishedAt)
		}
	}
	if now.Before(floor) {
		return floor
	}
	return now
}

func (s *Store) Deny(id, reviewer string) (model.Receipt, error) {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	record, found := s.state.Requests[id]
	if !found || record.State != "pending" {
		return model.Receipt{}, ErrExecutionRejected
	}
	plan, err := resolveExecutionPlan(record.Request, s.capabilities, now, s.requestMaxTTL, s.execution)
	if err != nil {
		return model.Receipt{}, ErrExecutionRejected
	}
	eventTime := monotonicRecordTime(record, now)
	receipt, err := s.newReceipt(record.Request, model.DecisionDeny, reviewer, plan, eventTime)
	if err != nil {
		return model.Receipt{}, err
	}
	record = cloneRecord(record)
	record.State = "denied"
	record.Receipts = append(record.Receipts, Delivery{Receipt: receipt})
	next := clonePersistedState(s.state)
	next.Requests[id] = record
	if err := s.commit(next); err != nil {
		return model.Receipt{}, err
	}
	return receipt, nil
}

func (s *Store) newReceipt(request model.Request, decision, reviewer string, plan ExecutionPlan, now time.Time) (model.Receipt, error) {
	id, err := model.NewRandom("rec_", 18)
	if err != nil {
		return model.Receipt{}, err
	}
	receipt := model.Receipt{ID: id, RequestID: request.ID, RequestDigest: request.Digest, Decision: decision, Reviewer: reviewer, CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(s.receiptTTL))}
	if request.Version == model.RequestVersionV1 {
		receipt.Version = model.ReceiptVersionV2
		receipt.AdapterVersion = plan.LegacyAdapter
	} else {
		receipt.Version = model.ReceiptVersion
		receipt.ProfileID = plan.ProfileID
		receipt.ProfileVersion = plan.ProfileVersion
		receipt.PlanDigest = plan.Digest
	}
	if err := model.ValidateReceipt(receipt, now, s.receiptTTL); err != nil {
		return model.Receipt{}, err
	}
	if err := model.SignReceipt(&receipt, s.privateKey); err != nil {
		return model.Receipt{}, err
	}
	return receipt, nil
}

func (s *Store) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now().UTC())
}

func (s *Store) sweepLocked(now time.Time) {
	prune := s.expiredIDs(now)
	if len(prune) == 0 {
		return
	}
	next := clonePersistedState(s.state)
	for _, id := range prune {
		delete(next.Requests, id)
	}
	_ = s.commit(next)
}

func (s *Store) expiredIDs(now time.Time) []string {
	// Current receipt TTL is an admission control, not a history-retention
	// control: shrinking it must not make a restart erase valid receipts.
	cutoff := now.Add(-model.PersistedReceiptMaxLifetime)
	var prune []string
	for id, record := range s.state.Requests {
		if record.State == attemptStatusRunning {
			continue
		}
		expires, err := time.Parse(time.RFC3339, record.Request.ExpiresAt)
		if err == nil && !expires.After(now) && !hasCurrentUndeliveredReceipt(record, now) {
			prune = append(prune, id)
			continue
		}
		if isTerminal(record.State) && allDeliveredAfter(record, cutoff) {
			prune = append(prune, id)
		}
	}
	return prune
}

func hasCurrentUndeliveredReceipt(record Record, now time.Time) bool {
	for _, delivery := range record.Receipts {
		if delivery.Delivered {
			continue
		}
		expires, err := time.Parse(time.RFC3339, delivery.Receipt.ExpiresAt)
		if err == nil && expires.After(now) {
			return true
		}
	}
	return false
}

func isTerminal(state string) bool {
	return state == "denied" || state == model.DecisionExecuted || state == "manually_executed"
}

func allDeliveredAfter(record Record, cutoff time.Time) bool {
	for _, delivery := range record.Receipts {
		if !delivery.Delivered {
			return false
		}
		created, err := time.Parse(time.RFC3339, delivery.Receipt.CreatedAt)
		if err != nil || !created.Before(cutoff) {
			return false
		}
	}
	return true
}

func (s *Store) MarkDelivered(receiptID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, record := range s.state.Requests {
		for index := range record.Receipts {
			if record.Receipts[index].Receipt.ID != receiptID {
				continue
			}
			if record.Receipts[index].Delivered {
				return nil
			}
			record = cloneRecord(record)
			record.Receipts[index].Delivered = true
			next := clonePersistedState(s.state)
			next.Requests[id] = record
			return s.commit(next)
		}
	}
	return errors.New("receipt not found")
}

func (s *Store) Undelivered() []model.Receipt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var receipts []model.Receipt
	for _, record := range s.state.Requests {
		for _, delivery := range record.Receipts {
			if !delivery.Delivered {
				receipts = append(receipts, delivery.Receipt)
			}
		}
	}
	// Stable ordering preserves the durable append order for receipts created
	// in the same RFC3339 second, especially approval followed by execution.
	sort.SliceStable(receipts, func(i, j int) bool {
		return receipts[i].CreatedAt < receipts[j].CreatedAt
	})
	return receipts
}

func (s *Store) RecordPage(limit int, cursor string) ([]Record, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]paging.Key, 0, len(s.state.Requests))
	for id, record := range s.state.Requests {
		createdAt, err := time.Parse(time.RFC3339, record.Request.CreatedAt)
		if err != nil {
			return nil, "", errors.New("invalid stored request timestamp")
		}
		keys = append(keys, paging.Key{ID: id, CreatedAt: createdAt})
	}
	pageKeys, next, err := paging.Page(keys, limit, cursor)
	if err != nil {
		return nil, "", err
	}
	page := make([]Record, 0, len(pageKeys))
	for _, key := range pageKeys {
		page = append(page, cloneRecord(s.state.Requests[key.ID]))
	}
	return page, next, nil
}

func (s *Store) Record(id string) (Record, *ExecutionPlan, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, found := s.state.Requests[id]
	if !found {
		return Record{}, nil, false
	}
	if (record.State == attemptStatusRunning || record.State == model.DecisionExecuted) && len(record.Attempts) != 0 {
		plan, _ := persistedExecutionPlan(record)
		return cloneRecord(record), plan, true
	}
	plan, err := resolveExecutionPlan(record.Request, s.capabilities, s.now().UTC(), s.requestMaxTTL, s.execution)
	if err != nil {
		return cloneRecord(record), nil, true
	}
	return cloneRecord(record), cloneExecutionPlan(&plan), true
}

// persistedExecutionPlan returns the immutable plan that admitted the most
// recent attempt. Attempt history and completed/running review must never be
// silently re-resolved through current configuration. A failed or uncertain
// retry instead obtains a fresh actionable plan through Record.
func persistedExecutionPlan(record Record) (*ExecutionPlan, bool) {
	if len(record.Attempts) == 0 {
		return nil, false
	}
	plan := record.Attempts[len(record.Attempts)-1].Plan
	if plan == nil || verifyExecutionPlanDigest(*plan) != nil || record.Attempts[len(record.Attempts)-1].PlanDigest != plan.Digest {
		return nil, true
	}
	return cloneExecutionPlan(plan), true
}

func (s *Store) validateLoaded() error {
	publicKey := s.privateKey.Public().(ed25519.PublicKey)
	for id, record := range s.state.Requests {
		if err := s.validateLoadedRecord(id, record, publicKey); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) validateLoadedRecord(id string, record Record, publicKey ed25519.PublicKey) error {
	if id != record.Request.ID || len(record.Receipts) > maxReceiptsPerRecord || len(record.Attempts) > maxExecutionAttempts {
		return errors.New("invalid bounded trusted record")
	}
	if err := s.validateStoredRequest(record.Request); err != nil {
		return err
	}
	requestCreated, createdErr := time.Parse(time.RFC3339, record.Request.CreatedAt)
	requestExpires, expiresErr := time.Parse(time.RFC3339, record.Request.ExpiresAt)
	if createdErr != nil || expiresErr != nil {
		return errors.New("invalid persisted request window")
	}
	state := "pending"
	newApprovals, executed := 0, 0
	var approvalReceipts []model.Receipt
	var executedReceipt *model.Receipt
	var previousReceiptCreated time.Time
	for _, delivery := range record.Receipts {
		receipt := delivery.Receipt
		_, err := time.Parse(time.RFC3339, receipt.ExpiresAt)
		if err != nil || model.ValidatePersistedReceipt(receipt) != nil || model.VerifyReceiptSignature(receipt, publicKey) != nil {
			return errors.New("invalid trusted receipt")
		}
		receiptCreated, err := time.Parse(time.RFC3339, receipt.CreatedAt)
		if err != nil || receiptCreated.Before(requestCreated) || !receiptCreated.Before(requestExpires) || (!previousReceiptCreated.IsZero() && receiptCreated.Before(previousReceiptCreated)) {
			return errors.New("trusted receipt timestamp is outside request lifetime")
		}
		if receipt.RequestID != id || receipt.RequestDigest != record.Request.Digest {
			return errors.New("trusted receipt binding mismatch")
		}
		nextState, err := model.NextRequestState(state, receipt.Decision)
		if err != nil {
			return err
		}
		state = nextState
		if receipt.Decision == model.DecisionApproveForExecution {
			newApprovals++
			approvalReceipts = append(approvalReceipts, receipt)
		}
		if receipt.Decision == model.DecisionExecuted {
			executed++
			copy := receipt
			executedReceipt = &copy
		}
		previousReceiptCreated = receiptCreated
	}
	if len(record.Attempts) == 0 {
		if record.State != state {
			return errors.New("persisted request state does not match receipts")
		}
		return nil
	}
	if newApprovals != len(record.Attempts) || executed > 1 || (state != "approved_for_execution" && state != model.DecisionExecuted) {
		return errors.New("execution receipts do not match attempts")
	}
	for index, attempt := range record.Attempts {
		if err := validateAttempt(attempt, record.Request); err != nil {
			return err
		}
		if record.Request.Version == model.RequestVersion && (index >= len(approvalReceipts) || approvalReceipts[index].PlanDigest != attempt.PlanDigest || approvalReceipts[index].ProfileID != attempt.ProfileID || approvalReceipts[index].ProfileVersion != attempt.ProfileVersion) {
			return errors.New("approval receipt does not bind the execution attempt")
		}
		if index != len(record.Attempts)-1 && attempt.Status == attemptStatusRunning {
			return errors.New("nonfinal execution attempt is running")
		}
	}
	last := record.Attempts[len(record.Attempts)-1]
	if last.Status == attemptStatusSucceeded {
		if executed != 1 || record.State != model.DecisionExecuted || (record.Request.Version == model.RequestVersion && (executedReceipt == nil || executedReceipt.PlanDigest != last.PlanDigest)) {
			return errors.New("successful attempt lacks executed receipt")
		}
		return nil
	}
	if executed != 0 || record.State != last.Status {
		return errors.New("unfinished execution attempt state mismatch")
	}
	return nil
}

func validateAttempt(attempt ExecutionAttempt, request model.Request) error {
	if len(attempt.ID) < 24 || len(attempt.ID) > 84 || !strings.HasPrefix(attempt.ID, "att_") || !safeAttemptText(attempt.ID, 84) || attempt.RequestDigest != request.Digest || !safeAttemptText(attempt.Reviewer, 254) {
		return errors.New("invalid execution attempt binding")
	}
	if request.Version == model.RequestVersionV1 {
		if attempt.AdapterVersion != model.AdapterGitHubAddCollaboratorV1 {
			return errors.New("invalid legacy attempt adapter")
		}
		if attempt.Plan != nil && (verifyExecutionPlanDigest(*attempt.Plan) != nil || attempt.PlanDigest != attempt.Plan.Digest || attempt.Plan.RequestDigest != request.Digest) {
			return errors.New("invalid legacy attempt plan")
		}
	} else if attempt.AdapterVersion != "" || attempt.ProfileID != model.ProfileGitHubCommandID || attempt.ProfileVersion != model.ProfileGitHubCommandVersion || attempt.Plan == nil || attempt.PlanDigest != attempt.Plan.Digest || verifyExecutionPlanDigest(*attempt.Plan) != nil || attempt.Plan.RequestDigest != request.Digest || attempt.Plan.ProfileID != request.ProfileID || attempt.Plan.ProfileVersion != request.ProfileVersion || !slices.Equal(attempt.Plan.Argv, request.Argv) {
		return errors.New("invalid command attempt plan")
	}
	if attempt.Status != attemptStatusRunning && attempt.Status != attemptStatusFailed && attempt.Status != attemptStatusUncertain && attempt.Status != attemptStatusSucceeded {
		return errors.New("invalid execution attempt status")
	}
	requestCreated, createdErr := time.Parse(time.RFC3339, request.CreatedAt)
	requestExpires, expiresErr := time.Parse(time.RFC3339, request.ExpiresAt)
	started, startErr := time.Parse(time.RFC3339, attempt.StartedAt)
	if createdErr != nil || expiresErr != nil || startErr != nil || started.Before(requestCreated) || !started.Before(requestExpires) {
		return errors.New("invalid execution attempt start")
	}
	if attempt.Status == attemptStatusRunning {
		if attempt.FinishedAt != "" || attempt.FailureCode != "" || attempt.OutputPreview != nil {
			return errors.New("running execution attempt has completion data")
		}
		return nil
	}
	finished, err := time.Parse(time.RFC3339, attempt.FinishedAt)
	if err != nil || finished.Before(started) || !validFailureCode(attempt.FailureCode, attempt.Status) {
		return errors.New("invalid execution attempt completion")
	}
	if !validExecutionOutputPreview(attempt.OutputPreview) {
		return errors.New("invalid execution output preview")
	}
	return nil
}

func validExecutionOutputPreview(preview *ExecutionOutputPreview) bool {
	if preview == nil {
		return true
	}
	if len(preview.Stdout) > maxExecutionOutputPreviewBytes || len(preview.Stderr) > maxExecutionOutputPreviewBytes || !utf8.ValidString(preview.Stdout) || !utf8.ValidString(preview.Stderr) {
		return false
	}
	for _, text := range []string{preview.Stdout, preview.Stderr} {
		for _, value := range text {
			if (unicode.IsControl(value) && value != '\n' && value != '\t') || unicode.Is(unicode.Cf, value) || isOutputNoncharacter(value) {
				return false
			}
		}
		if model.ContainsLikelyCredential(text) {
			return false
		}
	}
	return true
}

func safeAttemptText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}

func validFailureCode(code, status string) bool {
	if status == attemptStatusSucceeded {
		return code == ""
	}
	switch code {
	case "missing_executable", "start_failed", "preparation_failed", "plan_tampered", "executable_changed", "nonzero_exit", "timed_out", "cancelled", "interrupted", "expired_during_execution", "completion_persistence_failed":
		return true
	default:
		return false
	}
}

func (s *Store) commit(next persistedState) error {
	if err := s.save(s.path, next); err != nil {
		// Keep the last acknowledged in-memory state. Save can fail after rename
		// when the parent-directory fsync fails; reloading that file would expose
		// an unacknowledged completion as durable and could publish an executed
		// receipt. The caller may now persist a conservative uncertain fallback.
		return err
	}
	s.state = next
	return nil
}

func clonePersistedState(state persistedState) persistedState {
	copy := persistedState{Requests: make(map[string]Record, len(state.Requests))}
	for id, record := range state.Requests {
		copy.Requests[id] = cloneRecord(record)
	}
	return copy
}

func actionTime(request model.Request) time.Time {
	expires, err := time.Parse(time.RFC3339, request.ExpiresAt)
	if err != nil {
		return time.Time{}
	}
	return expires.Add(-time.Second)
}

func cloneRecord(record Record) Record {
	copy := record
	copy.Request = cloneRequest(record.Request)
	copy.Receipts = append([]Delivery(nil), record.Receipts...)
	copy.Attempts = append([]ExecutionAttempt(nil), record.Attempts...)
	for index := range copy.Attempts {
		copy.Attempts[index].Plan = cloneExecutionPlan(record.Attempts[index].Plan)
		copy.Attempts[index].OutputPreview = cloneExecutionOutputPreview(record.Attempts[index].OutputPreview)
	}
	return copy
}

func cloneRequest(request model.Request) model.Request {
	copy := request
	if request.Arguments != nil {
		copy.Arguments = make(map[string]string, len(request.Arguments))
		for key, value := range request.Arguments {
			copy.Arguments[key] = value
		}
	}
	copy.Argv = append([]string(nil), request.Argv...)
	return copy
}

func cloneExecutionPlan(plan *ExecutionPlan) *ExecutionPlan {
	if plan == nil {
		return nil
	}
	copy := *plan
	copy.Argv = append([]string(nil), plan.Argv...)
	copy.EnvironmentPolicy = append([]string(nil), plan.EnvironmentPolicy...)
	return &copy
}

func cloneExecutionOutputPreview(preview *ExecutionOutputPreview) *ExecutionOutputPreview {
	if preview == nil {
		return nil
	}
	copy := *preview
	return &copy
}

func (s *Store) validateStoredRequest(request model.Request) error {
	// History remains readable across capability removal and config change. A
	// pending legacy record can consequently be non-actionable, but execution
	// and review resolution still fail safely through resolveExecutionPlan.
	return model.ValidatePersistedRequest(request)
}
