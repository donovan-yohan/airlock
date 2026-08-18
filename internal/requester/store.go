package requester

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/donovan-yohan/airlock/internal/model"
	"github.com/donovan-yohan/airlock/internal/paging"
	"github.com/donovan-yohan/airlock/internal/statefile"
)

type Record struct {
	Request  model.Request   `json:"request"`
	State    string          `json:"state"`
	Receipts []model.Receipt `json:"receipts"`
}

type persistedState struct {
	Catalog  *model.Catalog    `json:"catalog,omitempty"`
	Requests map[string]Record `json:"requests"`
}

type Store struct {
	mu            sync.RWMutex
	path          string
	publicKey     ed25519.PublicKey
	requestMaxTTL time.Duration
	catalogMaxTTL time.Duration
	receiptMaxTTL time.Duration
	now           func() time.Time
	state         persistedState
}

// ErrCapacity identifies a retryable requester storage-capacity failure.
// Validation and policy rejections remain separate, non-retryable errors.
var ErrCapacity = errors.New("requester capacity unavailable")

type CreateInput struct {
	ProfileID      string   `json:"profile_id"`
	ProfileVersion string   `json:"profile_version"`
	Argv           []string `json:"argv"`
	Reason         string   `json:"reason"`
	TTLSeconds     int64    `json:"ttl_seconds"`
}

func NewStore(stateDir string, publicKey ed25519.PublicKey, requestMaxTTL, catalogMaxTTL, receiptMaxTTL time.Duration) (*Store, error) {
	store := &Store{
		path: filepath.Join(stateDir, "requester-state.json"), publicKey: append(ed25519.PublicKey(nil), publicKey...),
		requestMaxTTL: requestMaxTTL, catalogMaxTTL: catalogMaxTTL, receiptMaxTTL: receiptMaxTTL,
		now: time.Now, state: persistedState{Requests: map[string]Record{}},
	}
	if err := statefile.Load(store.path, &store.state); err != nil {
		return nil, err
	}
	if store.state.Requests == nil {
		store.state.Requests = map[string]Record{}
	}
	// Loading is all-or-nothing: complete stable-envelope and signature
	// validation must finish before retention can mutate or rewrite any bytes.
	// A bad signature/corrupt record is evidence, not garbage to silently drop.
	if err := store.validateLoaded(); err != nil {
		return nil, errors.New("persisted requester state is invalid")
	}
	// Retention is the sole startup deletion path, and it runs only after the
	// whole candidate snapshot was accepted.
	expired := store.expiredIDs(store.now().UTC())
	for _, id := range expired {
		delete(store.state.Requests, id)
	}
	if len(expired) != 0 {
		if err := store.commit(store.state); err != nil {
			return nil, fmt.Errorf("persist recovered requester state: %w", err)
		}
	}
	return store, nil
}

func (s *Store) ImportCatalog(catalog model.Catalog) error {
	now := s.now().UTC()
	if err := model.ValidateCatalog(catalog, now, s.catalogMaxTTL); err != nil {
		return err
	}
	if err := model.VerifyCatalogSignature(catalog, s.publicKey); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Catalog != nil {
		currentIssued, _ := time.Parse(time.RFC3339, s.state.Catalog.IssuedAt)
		incomingIssued, _ := time.Parse(time.RFC3339, catalog.IssuedAt)
		if incomingIssued.Before(currentIssued) {
			return errors.New("catalog rollback refused")
		}
		if incomingIssued.Equal(currentIssued) {
			if catalog.Signature == s.state.Catalog.Signature {
				return nil
			}
			return errors.New("catalog equivocation refused")
		}
	}
	next := clonePersistedState(s.state)
	next.Catalog = cloneCatalog(&catalog)
	return s.commit(next)
}

func (s *Store) Create(input CreateInput) (Record, error) {
	now := s.now().UTC()
	// Reject current proposal argv before any canonical digest is computed or
	// requester record is constructed.
	if err := model.ValidateArgv(input.Argv); err != nil {
		return Record{}, err
	}
	if err := model.ValidateCommandReason(input.Reason); err != nil {
		return Record{}, err
	}
	if input.TTLSeconds < 60 || time.Duration(input.TTLSeconds)*time.Second > s.requestMaxTTL {
		return Record{}, errors.New("request TTL is outside configured bounds")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sweepLocked(now); err != nil {
		return Record{}, fmt.Errorf("prune requester state: %w", err)
	}
	if len(s.state.Requests) >= maxRequesterRequests {
		return Record{}, errors.New("requester request store is full")
	}
	if s.state.Catalog == nil {
		return Record{}, errors.New("no trusted catalog is installed")
	}
	if err := model.ValidateCatalog(*s.state.Catalog, now, s.catalogMaxTTL); err != nil {
		return Record{}, fmt.Errorf("installed catalog is not current: %w", err)
	}
	if s.state.Catalog.Version != model.CatalogVersion {
		return Record{}, errors.New("installed catalog does not support command proposals")
	}
	profile, found := findProfile(s.state.Catalog.Profiles, input.ProfileID, input.ProfileVersion)
	if !found {
		return Record{}, errors.New("unknown command profile")
	}
	requestID, err := model.NewRandom("req_", 18)
	if err != nil {
		return Record{}, err
	}
	nonce, err := model.NewRandom("", 24)
	if err != nil {
		return Record{}, err
	}
	expires := now.Add(time.Duration(input.TTLSeconds) * time.Second)
	catalogExpires, _ := time.Parse(time.RFC3339, s.state.Catalog.ExpiresAt)
	if expires.After(catalogExpires) {
		return Record{}, errors.New("request would outlive the installed catalog")
	}
	request := model.Request{
		Version: model.RequestVersion, ID: requestID, ProfileID: input.ProfileID, ProfileVersion: input.ProfileVersion,
		Argv: append([]string(nil), input.Argv...), Reason: input.Reason,
		CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(expires), Nonce: nonce,
	}
	if err := model.SetRequestDigest(&request); err != nil {
		return Record{}, err
	}
	if err := model.ValidateRequest(request, now, s.requestMaxTTL); err != nil {
		return Record{}, err
	}
	if err := model.ValidateRequestAgainstProfile(request, profile); err != nil {
		return Record{}, err
	}
	record := Record{Request: request, State: "pending", Receipts: []model.Receipt{}}
	next := clonePersistedState(s.state)
	next.Requests[request.ID] = record
	if err := s.commit(next); err != nil {
		return Record{}, err
	}
	return cloneRecord(record), nil
}

func (s *Store) AcceptReceipt(receipt model.Receipt) (Record, error) {
	now := s.now().UTC()
	if err := model.ValidateReceipt(receipt, now, s.receiptMaxTTL); err != nil {
		return Record{}, err
	}
	if err := model.VerifyReceiptSignature(receipt, s.publicKey); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sweepLocked(now); err != nil {
		return Record{}, fmt.Errorf("prune requester state before receipt: %w", err)
	}
	record, found := s.state.Requests[receipt.RequestID]
	if !found {
		return Record{}, errors.New("receipt references an unknown request")
	}
	if len(record.Receipts) >= maxRequesterReceipts {
		return Record{}, errors.New("receipt history exceeds the protocol limit")
	}
	if !receiptProtocolMatchesRequest(record.Request, receipt) {
		return Record{}, errors.New("receipt protocol does not match request protocol")
	}
	requestCreated, _ := time.Parse(time.RFC3339, record.Request.CreatedAt)
	requestExpires, _ := time.Parse(time.RFC3339, record.Request.ExpiresAt)
	receiptCreated, _ := time.Parse(time.RFC3339, receipt.CreatedAt)
	if receiptCreated.Before(requestCreated) || !receiptCreated.Before(requestExpires) {
		return Record{}, errors.New("receipt timestamp falls outside the request lifetime")
	}
	if subtle.ConstantTimeCompare([]byte(receipt.RequestDigest), []byte(record.Request.Digest)) != 1 {
		return Record{}, errors.New("receipt request digest mismatch")
	}
	for _, existing := range record.Receipts {
		if existing.ID == receipt.ID || existing.Signature == receipt.Signature {
			return Record{}, errors.New("receipt replay refused")
		}
	}
	if len(record.Receipts) != 0 {
		lastCreated, _ := time.Parse(time.RFC3339, record.Receipts[len(record.Receipts)-1].CreatedAt)
		if receiptCreated.Before(lastCreated) {
			return Record{}, errors.New("receipt timestamp precedes the prior decision")
		}
		if receipt.Version == model.ReceiptVersion && receipt.Decision == model.DecisionExecuted && !sameCurrentPlan(record.Receipts[len(record.Receipts)-1], receipt) {
			return Record{}, errors.New("execution receipt plan does not match the latest approval")
		}
	}
	next, err := model.NextRequestState(record.State, receipt.Decision)
	if err != nil {
		return Record{}, err
	}
	record.State = next
	record.Receipts = append(record.Receipts, receipt)
	nextState := clonePersistedState(s.state)
	nextState.Requests[receipt.RequestID] = record
	if err := s.commit(nextState); err != nil {
		return Record{}, err
	}
	return cloneRecord(record), nil
}

func (s *Store) Catalog() (*model.Catalog, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state.Catalog == nil {
		return nil, false
	}
	return cloneCatalog(s.state.Catalog), true
}

const (
	// Keep the worst-case serialized requester state comfortably below the
	// statefile package's 16 MiB atomic-write ceiling. A full store rejects new
	// requests but can still accept receipts for existing records.
	maxRequesterRequests = model.MaxRequesterRequests
	// A trusted request can have at most four approvals/retries followed by one
	// execution receipt. Bounding that protocol history keeps an otherwise
	// replay-safe sequence from growing requester state without limit.
	maxRequesterReceipts = 5

	// The bounded read contract lives in internal/paging; these are the
	// requester-facing names for it.
	MaxRecordPage     = paging.MaxPage
	DefaultRecordPage = paging.DefaultPage
	MaxCursorBytes    = paging.MaxCursorBytes
)

// RecordPage bounds reads from untrusted clients. The opaque keyset cursor
// resumes after the last returned request even if that record is later pruned.
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
	// Clone only what the page returns; the whole store is never copied.
	page := make([]Record, 0, len(pageKeys))
	for _, key := range pageKeys {
		page = append(page, cloneRecord(s.state.Requests[key.ID]))
	}
	return page, next, nil
}

func (s *Store) ActionableRequestPage(limit int, cursor string) ([]model.Request, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now().UTC()
	keys := make([]paging.Key, 0, len(s.state.Requests))
	for id, record := range s.state.Requests {
		if record.State != "pending" && record.State != "approved" && record.State != "approved_for_execution" {
			continue
		}
		expires, err := time.Parse(time.RFC3339, record.Request.ExpiresAt)
		if err != nil || !expires.After(now) {
			continue
		}
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
	requests := make([]model.Request, 0, len(pageKeys))
	for _, key := range pageKeys {
		requests = append(requests, cloneRequest(s.state.Requests[key.ID].Request))
	}
	return requests, next, nil
}

func (s *Store) Record(id string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, found := s.state.Requests[id]
	return cloneRecord(record), found
}

// validateLoaded verifies the complete decoded candidate snapshot before any
// recovery/pruning write. Current limits govern ImportCatalog/Create/Receipt
// admission; durable history is bound only by protocol-envelope limits.
func (s *Store) validateLoaded() error {
	if s.state.Catalog != nil {
		if err := model.VerifyCatalogSignature(*s.state.Catalog, s.publicKey); err != nil {
			return err
		}
		if err := model.ValidatePersistedCatalog(*s.state.Catalog); err != nil {
			return err
		}
	}
	for id, record := range s.state.Requests {
		if err := s.validateLoadedRecord(id, record); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) validateLoadedRecord(id string, record Record) error {
	if id != record.Request.ID {
		return errors.New("request map key mismatch")
	}
	if len(record.Receipts) > maxRequesterReceipts {
		return errors.New("persisted receipt history exceeds the protocol limit")
	}
	requestCreated, createdErr := time.Parse(time.RFC3339, record.Request.CreatedAt)
	requestExpires, expiresErr := time.Parse(time.RFC3339, record.Request.ExpiresAt)
	if createdErr != nil || expiresErr != nil {
		return errors.New("invalid persisted request timestamps")
	}
	if err := model.ValidatePersistedRequest(record.Request); err != nil {
		return err
	}
	state := "pending"
	var previousReceiptCreated time.Time
	seenReceiptIDs := make(map[string]struct{}, len(record.Receipts))
	seenReceiptSignatures := make(map[string]struct{}, len(record.Receipts))
	for receiptIndex, receipt := range record.Receipts {
		if !receiptProtocolMatchesRequest(record.Request, receipt) {
			return errors.New("persisted receipt protocol does not match request protocol")
		}
		if _, exists := seenReceiptIDs[receipt.ID]; exists {
			return errors.New("persisted receipt replay")
		}
		if _, exists := seenReceiptSignatures[receipt.Signature]; exists {
			return errors.New("persisted receipt replay")
		}
		seenReceiptIDs[receipt.ID] = struct{}{}
		seenReceiptSignatures[receipt.Signature] = struct{}{}
		if err := model.VerifyReceiptSignature(receipt, s.publicKey); err != nil {
			return err
		}
		receiptCreated, createdErr := time.Parse(time.RFC3339, receipt.CreatedAt)
		_, expiresErr := time.Parse(time.RFC3339, receipt.ExpiresAt)
		if createdErr != nil || expiresErr != nil {
			return errors.New("invalid persisted receipt timestamps")
		}
		if err := model.ValidatePersistedReceipt(receipt); err != nil {
			return err
		}
		if receiptCreated.Before(requestCreated) || !receiptCreated.Before(requestExpires) || (!previousReceiptCreated.IsZero() && receiptCreated.Before(previousReceiptCreated)) {
			return errors.New("persisted receipt timestamp falls outside the request lifetime")
		}
		if receipt.RequestID != id || receipt.RequestDigest != record.Request.Digest {
			return errors.New("persisted receipt binding mismatch")
		}
		if receipt.Version == model.ReceiptVersion && receipt.Decision == model.DecisionExecuted {
			if receiptIndex == 0 || !sameCurrentPlan(record.Receipts[receiptIndex-1], receipt) {
				return errors.New("persisted execution receipt plan does not match the latest approval")
			}
		}
		var err error
		state, err = model.NextRequestState(state, receipt.Decision)
		if err != nil {
			return err
		}
		previousReceiptCreated = receiptCreated
	}
	if state != record.State {
		return errors.New("persisted request state does not match receipts")
	}
	return nil
}

func receiptProtocolMatchesRequest(request model.Request, receipt model.Receipt) bool {
	if request.Version == model.RequestVersion {
		return receipt.Version == model.ReceiptVersion
	}
	return request.Version == model.RequestVersionV1 && (receipt.Version == model.ReceiptVersionV1 || receipt.Version == model.ReceiptVersionV2)
}

func sameCurrentPlan(approval, execution model.Receipt) bool {
	return approval.Version == model.ReceiptVersion &&
		approval.Decision == model.DecisionApproveForExecution &&
		approval.ProfileID == execution.ProfileID &&
		approval.ProfileVersion == execution.ProfileVersion &&
		approval.PlanDigest == execution.PlanDigest
}

// expiredIDs lists requests kept past the latest point at which a timely
// trusted receipt could still be valid and delivered. The caller holds s.mu,
// except during single-threaded construction in NewStore.
func (s *Store) expiredIDs(now time.Time) []string {
	var prune []string
	for id, record := range s.state.Requests {
		requestExpires, err := time.Parse(time.RFC3339, record.Request.ExpiresAt)
		if err != nil {
			prune = append(prune, id)
			continue
		}
		retainUntil := requestExpires.Add(model.PersistedReceiptMaxLifetime)
		for _, receipt := range record.Receipts {
			if receiptExpires, err := time.Parse(time.RFC3339, receipt.ExpiresAt); err == nil && receiptExpires.After(retainUntil) {
				retainUntil = receiptExpires
			}
		}
		if !retainUntil.After(now) {
			prune = append(prune, id)
		}
	}
	return prune
}

func (s *Store) sweepLocked(now time.Time) error {
	prune := s.expiredIDs(now)
	if len(prune) == 0 {
		return nil
	}
	next := clonePersistedState(s.state)
	for _, id := range prune {
		delete(next.Requests, id)
	}
	return s.commit(next)
}

func (s *Store) commit(next persistedState) error {
	if err := statefile.Save(s.path, next); err != nil {
		var recovered persistedState
		if loadErr := statefile.Load(s.path, &recovered); loadErr == nil && recovered.Requests != nil {
			s.state = recovered
		}
		if errors.Is(err, statefile.ErrTooLarge) {
			return ErrCapacity
		}
		return err
	}
	s.state = next
	return nil
}

func clonePersistedState(state persistedState) persistedState {
	copy := persistedState{Catalog: cloneCatalog(state.Catalog), Requests: make(map[string]Record, len(state.Requests))}
	for id, record := range state.Requests {
		copy.Requests[id] = cloneRecord(record)
	}
	return copy
}

func cloneCatalog(c *model.Catalog) *model.Catalog {
	if c == nil {
		return nil
	}
	copy := *c
	copy.Profiles = append([]model.CommandProfile(nil), c.Profiles...)
	copy.Capabilities = append([]model.Capability(nil), c.Capabilities...)
	for i := range copy.Capabilities {
		copy.Capabilities[i].Actions = append([]string(nil), c.Capabilities[i].Actions...)
		copy.Capabilities[i].Constraints.Permissions = append([]string(nil), c.Capabilities[i].Constraints.Permissions...)
	}
	return &copy
}

func cloneRecord(record Record) Record {
	copy := record
	copy.Request = cloneRequest(record.Request)
	copy.Receipts = append([]model.Receipt(nil), record.Receipts...)
	return copy
}

func cloneRequest(request model.Request) model.Request {
	copy := request
	copy.Arguments = cloneMap(request.Arguments)
	copy.Argv = append([]string(nil), request.Argv...)
	return copy
}

func findProfile(profiles []model.CommandProfile, id, version string) (model.CommandProfile, bool) {
	for _, profile := range profiles {
		if profile.ID == id && profile.Version == version {
			return profile, true
		}
	}
	return model.CommandProfile{}, false
}

func cloneMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}
