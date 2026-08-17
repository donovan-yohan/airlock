package trusted

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	// trusted state comfortably below statefile's shared 16 MiB atomic limit.
	maxTrustedRequests     = 1024
	maxExecutionAttempts   = 4
	maxReceiptsPerRecord   = maxExecutionAttempts + 1
	maxExecutionPathBytes  = 1024
	attemptStatusRunning   = "running"
	attemptStatusFailed    = "failed"
	attemptStatusUncertain = "uncertain"
	attemptStatusSucceeded = "succeeded"
)

var (
	ErrExecutionUnavailable = errors.New("trusted execution is not configured")
	ErrExecutionActive      = errors.New("an execution attempt is already running")
	ErrExecutionRejected    = errors.New("execution is not allowed for this request state")
	ErrExecutionFailed      = errors.New("trusted provider invocation failed")
	ErrExecutionUncertain   = errors.New("provider outcome is uncertain; verify or explicitly retry")
)

// ExecutionConfig originates exclusively from strict trusted-node config. The
// requester never receives it, and plans are rederived from the request.
type ExecutionConfig struct {
	GitHubCLIPath   string
	GitHubConfigDir string
	Timeout         time.Duration
}

// ExecutionAttempt is bounded, sanitized local audit state. In particular it
// deliberately has no stdout, stderr, environment, provider response, or free
// form command field.
type ExecutionAttempt struct {
	ID             string `json:"id"`
	RequestDigest  string `json:"request_digest"`
	Reviewer       string `json:"reviewer"`
	AdapterVersion string `json:"adapter_version"`
	Status         string `json:"status"`
	StartedAt      string `json:"started_at"`
	FinishedAt     string `json:"finished_at,omitempty"`
	FailureCode    string `json:"failure_code,omitempty"`
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
	Run(context.Context, ExecutionPlan, []string) error
}

type directExecutionRunner struct{}

func (directExecutionRunner) Run(ctx context.Context, plan ExecutionPlan, environment []string) error {
	// Do not use a shell, PATH search, inherited environment, or request text.
	command := exec.CommandContext(ctx, plan.Executable, plan.Argv...)
	command.Env = append([]string(nil), environment...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func minimalChildEnvironment(configDir string) []string {
	// The child receives a complete fixed environment. In particular neither
	// inherited token/proxy variables nor the operator's HOME are propagated.
	return []string{
		"GH_CONFIG_DIR=" + configDir,
		"GH_PROMPT_DISABLED=1",
		"GH_NO_UPDATE_NOTIFIER=1",
		"NO_COLOR=1",
		"TERM=dumb",
		"HOME=" + configDir,
		"LC_ALL=C",
		"PATH=/usr/bin:/bin",
	}
}

type Store struct {
	mu            sync.RWMutex
	path          string
	privateKey    ed25519.PrivateKey
	capabilities  []config.TrustedCapability
	requestMaxTTL time.Duration
	receiptTTL    time.Duration
	execution     *ExecutionConfig
	runner        executionRunner
	save          func(string, any) error
	now           func() time.Time
	state         persistedState
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
		if err := validateExecutionConfig(execution[0]); err != nil {
			return nil, err
		}
		if err := statefile.EnsurePrivateDir(execution[0].GitHubConfigDir); err != nil {
			return nil, fmt.Errorf("prepare GitHub config directory: %w", err)
		}
		copy := execution[0]
		store.execution = &copy
	}
	if err := statefile.Load(store.path, &store.state); err != nil {
		return nil, err
	}
	if store.state.Requests == nil {
		store.state.Requests = map[string]Record{}
	}
	changed := store.sanitizeLoaded()
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
		record.Attempts[last].FinishedAt = model.Timestamp(store.now().UTC())
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
	for name, path := range map[string]string{"github cli path": value.GitHubCLIPath, "GitHub config directory": value.GitHubConfigDir} {
		if !validExecutionPath(path) {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if value.Timeout < time.Second || value.Timeout > 5*time.Minute {
		return errors.New("trusted execution timeout is outside bounds")
	}
	return nil
}

func validExecutionPath(path string) bool {
	if path == "" || len(path) > maxExecutionPathBytes || !utf8.ValidString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return false
	}
	for _, character := range path {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func (s *Store) Ingest(request model.Request) error {
	now := s.now().UTC()
	if _, err := validateAndPlan(request, s.capabilities, now, s.requestMaxTTL, s.planExecutable()); err != nil {
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

func (s *Store) Execute(ctx context.Context, id, reviewer string) error {
	plan, attemptID, deadline, err := s.reserveExecution(id, reviewer)
	if err != nil {
		return err
	}
	// Reservation commit above occurs while locked. Provider work intentionally
	// happens after releasing it, so sync and reviewers cannot deadlock behind
	// a slow process.
	executionContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	err = s.runner.Run(executionContext, plan, minimalChildEnvironment(s.execution.GitHubConfigDir))
	return s.completeExecution(id, attemptID, err, executionContext.Err())
}

func (s *Store) reserveExecution(id, reviewer string) (ExecutionPlan, string, time.Time, error) {
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
	plan, err := validateAndPlan(record.Request, s.capabilities, now, s.requestMaxTTL, s.execution.GitHubCLIPath)
	if err != nil {
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
	approval, err := s.newReceipt(record.Request, model.DecisionApproveForExecution, reviewer, plan.Adapter, now)
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
		ID: attemptID, RequestDigest: record.Request.Digest, Reviewer: reviewer, AdapterVersion: plan.Adapter,
		Status: attemptStatusRunning, StartedAt: model.Timestamp(now),
	})
	next := clonePersistedState(s.state)
	next.Requests[id] = record
	if err := s.commit(next); err != nil {
		return ExecutionPlan{}, "", time.Time{}, err
	}
	return plan, attemptID, deadline, nil
}

func (s *Store) completeExecution(id, attemptID string, runErr, contextErr error) error {
	if runErr != nil || contextErr != nil {
		status, code := executionFailureOutcome(runErr, contextErr)
		if err := s.completeAttempt(id, attemptID, status, code); err != nil {
			return ErrExecutionUncertain
		}
		if status == attemptStatusFailed {
			return ErrExecutionFailed
		}
		return ErrExecutionUncertain
	}
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
	receipt, err := s.newReceipt(record.Request, model.DecisionExecuted, record.Attempts[len(record.Attempts)-1].Reviewer, record.Attempts[len(record.Attempts)-1].AdapterVersion, now)
	if err != nil {
		s.mu.Unlock()
		_ = s.completeAttempt(id, attemptID, attemptStatusUncertain, "completion_persistence_failed")
		return ErrExecutionUncertain
	}
	record = cloneRecord(record)
	last := len(record.Attempts) - 1
	record.Attempts[last].Status = attemptStatusSucceeded
	record.Attempts[last].FinishedAt = model.Timestamp(now)
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
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.state.Requests[id]
	if !found || !lastAttemptIs(record, attemptID, attemptStatusRunning) {
		return errors.New("attempt record unavailable")
	}
	record = cloneRecord(record)
	last := len(record.Attempts) - 1
	record.Attempts[last].Status = status
	record.Attempts[last].FailureCode = code
	record.Attempts[last].FinishedAt = model.Timestamp(now)
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
	record.Attempts[last].FinishedAt = model.Timestamp(now)
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

func (s *Store) Deny(id, reviewer string) (model.Receipt, error) {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	record, found := s.state.Requests[id]
	if !found || record.State != "pending" {
		return model.Receipt{}, ErrExecutionRejected
	}
	plan, err := validateAndPlan(record.Request, s.capabilities, now, s.requestMaxTTL, s.planExecutable())
	if err != nil {
		return model.Receipt{}, ErrExecutionRejected
	}
	receipt, err := s.newReceipt(record.Request, model.DecisionDeny, reviewer, plan.Adapter, now)
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

func (s *Store) newReceipt(request model.Request, decision, reviewer, adapter string, now time.Time) (model.Receipt, error) {
	id, err := model.NewRandom("rec_", 18)
	if err != nil {
		return model.Receipt{}, err
	}
	receipt := model.Receipt{Version: model.ReceiptVersion, ID: id, RequestID: request.ID, RequestDigest: request.Digest, Decision: decision, Reviewer: reviewer, AdapterVersion: adapter, CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(s.receiptTTL))}
	if err := model.ValidateReceipt(receipt, now, s.receiptTTL); err != nil {
		return model.Receipt{}, err
	}
	if err := model.SignReceipt(&receipt, s.privateKey); err != nil {
		return model.Receipt{}, err
	}
	return receipt, nil
}

func (s *Store) planExecutable() string {
	if s.execution == nil {
		return ""
	}
	return s.execution.GitHubCLIPath
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
	cutoff := now.Add(-s.receiptTTL)
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

func (s *Store) Record(id string) (Record, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, found := s.state.Requests[id]
	if !found {
		return Record{}, "", false
	}
	plan, err := validateAndPlan(record.Request, s.capabilities, actionTime(record.Request), s.requestMaxTTL, s.planExecutable())
	if err != nil {
		return cloneRecord(record), "", true
	}
	return cloneRecord(record), plan.Display, true
}

func (s *Store) sanitizeLoaded() bool {
	publicKey := s.privateKey.Public().(ed25519.PublicKey)
	changed := false
	for id, record := range s.state.Requests {
		if err := s.validateLoadedRecord(id, record, publicKey); err != nil {
			delete(s.state.Requests, id)
			changed = true
		}
	}
	return changed
}

func (s *Store) validateLoadedRecord(id string, record Record, publicKey ed25519.PublicKey) error {
	if id != record.Request.ID || len(record.Receipts) > maxReceiptsPerRecord || len(record.Attempts) > maxExecutionAttempts {
		return errors.New("invalid bounded trusted record")
	}
	if _, err := validateAndPlan(record.Request, s.capabilities, actionTime(record.Request), s.requestMaxTTL, s.planExecutable()); err != nil {
		return err
	}
	requestCreated, createdErr := time.Parse(time.RFC3339, record.Request.CreatedAt)
	requestExpires, expiresErr := time.Parse(time.RFC3339, record.Request.ExpiresAt)
	if createdErr != nil || expiresErr != nil {
		return errors.New("invalid persisted request window")
	}
	state := "pending"
	newApprovals, executed := 0, 0
	var previousReceiptCreated time.Time
	for _, delivery := range record.Receipts {
		receipt := delivery.Receipt
		receiptExpiry, err := time.Parse(time.RFC3339, receipt.ExpiresAt)
		if err != nil || model.ValidateReceipt(receipt, receiptExpiry.Add(-time.Second), s.receiptTTL) != nil || model.VerifyReceiptSignature(receipt, publicKey) != nil {
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
		}
		if receipt.Decision == model.DecisionExecuted {
			executed++
		}
		previousReceiptCreated = receiptCreated
	}
	if len(record.Attempts) == 0 {
		if record.State != state {
			return errors.New("persisted request state does not match receipts")
		}
		return nil
	}
	if newApprovals != len(record.Attempts) || executed > 1 || state != "approved_for_execution" && state != model.DecisionExecuted {
		return errors.New("execution receipts do not match attempts")
	}
	for index, attempt := range record.Attempts {
		if err := validateAttempt(attempt, record.Request); err != nil {
			return err
		}
		if index != len(record.Attempts)-1 && attempt.Status == attemptStatusRunning {
			return errors.New("nonfinal execution attempt is running")
		}
	}
	last := record.Attempts[len(record.Attempts)-1]
	if last.Status == attemptStatusSucceeded {
		if executed != 1 || record.State != model.DecisionExecuted {
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
	if len(attempt.ID) < 24 || len(attempt.ID) > 84 || !strings.HasPrefix(attempt.ID, "att_") || !safeAttemptText(attempt.ID, 84) || attempt.RequestDigest != request.Digest || attempt.AdapterVersion != model.AdapterGitHubAddCollaboratorV1 || !safeAttemptText(attempt.Reviewer, 254) {
		return errors.New("invalid execution attempt binding")
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
		if attempt.FinishedAt != "" || attempt.FailureCode != "" {
			return errors.New("running execution attempt has completion data")
		}
		return nil
	}
	finished, err := time.Parse(time.RFC3339, attempt.FinishedAt)
	if err != nil || finished.Before(started) || !validFailureCode(attempt.FailureCode, attempt.Status) {
		return errors.New("invalid execution attempt completion")
	}
	return nil
}

func safeAttemptText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}

func validFailureCode(code, status string) bool {
	if status == attemptStatusSucceeded {
		return code == ""
	}
	switch code {
	case "missing_executable", "start_failed", "nonzero_exit", "timed_out", "cancelled", "interrupted", "expired_during_execution", "completion_persistence_failed":
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
	return copy
}

func cloneRequest(request model.Request) model.Request {
	copy := request
	copy.Arguments = make(map[string]string, len(request.Arguments))
	for key, value := range request.Arguments {
		copy.Arguments[key] = value
	}
	return copy
}
