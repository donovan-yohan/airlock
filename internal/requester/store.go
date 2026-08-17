package requester

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
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

type CreateInput struct {
	CapabilityID string            `json:"capability_id"`
	Action       string            `json:"action"`
	Arguments    map[string]string `json:"arguments"`
	Reason       string            `json:"reason"`
	TTLSeconds   int64             `json:"ttl_seconds"`
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
	// Recovery and retention prune the same loaded state, so they share one
	// serialization instead of writing the state file twice on startup.
	sanitized := store.sanitizeLoaded()
	expired := store.expiredIDs(store.now().UTC())
	for _, id := range expired {
		delete(store.state.Requests, id)
	}
	if sanitized || len(expired) != 0 {
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
	if err := model.ValidateReason(input.Reason); err != nil {
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
	capability, found := model.FindCapability(s.state.Catalog.Capabilities, input.CapabilityID)
	if !found {
		return Record{}, errors.New("unknown capability")
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
		Version: model.RequestVersion, ID: requestID, CapabilityID: input.CapabilityID,
		Action: input.Action, Arguments: cloneMap(input.Arguments), Reason: input.Reason,
		CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(expires), Nonce: nonce,
	}
	if err := model.SetRequestDigest(&request); err != nil {
		return Record{}, err
	}
	if err := model.ValidateRequest(request, now, s.requestMaxTTL); err != nil {
		return Record{}, err
	}
	if err := model.ValidateRequestAgainstCapability(request, capability); err != nil {
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
	record, found := s.state.Requests[receipt.RequestID]
	if !found {
		return Record{}, errors.New("receipt references an unknown request")
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
	maxRequesterRequests = 4096

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

func (s *Store) ActionableRequests() []model.Request {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now().UTC()
	requests := make([]model.Request, 0, len(s.state.Requests))
	for _, record := range s.state.Requests {
		if record.State != "pending" && record.State != "approved" && record.State != "approved_for_execution" {
			continue
		}
		expires, err := time.Parse(time.RFC3339, record.Request.ExpiresAt)
		if err != nil || !expires.After(now) {
			continue
		}
		requests = append(requests, cloneRequest(record.Request))
	}
	sort.Slice(requests, func(i, j int) bool {
		return requests[i].CreatedAt < requests[j].CreatedAt
	})
	return requests
}

func (s *Store) Record(id string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, found := s.state.Requests[id]
	return cloneRecord(record), found
}

// sanitizeLoaded drops records that no longer validate under the configured
// TTLs or trusted public key. This lets routine TTL tightening and key rotation
// recover on restart without trusting stale signatures or entering a crash
// loop. Invalid JSON and unsafe file permissions still fail in statefile.Load.
func (s *Store) sanitizeLoaded() bool {
	changed := false
	if s.state.Catalog != nil {
		if err := model.VerifyCatalogSignature(*s.state.Catalog, s.publicKey); err != nil {
			s.state.Catalog = nil
			changed = true
		} else if expires, err := time.Parse(time.RFC3339, s.state.Catalog.ExpiresAt); err != nil || model.ValidateCatalog(*s.state.Catalog, expires.Add(-time.Second), s.catalogMaxTTL) != nil {
			s.state.Catalog = nil
			changed = true
		}
	}
	for id, record := range s.state.Requests {
		if s.validateLoadedRecord(id, record) != nil {
			delete(s.state.Requests, id)
			changed = true
		}
	}
	return changed
}

func (s *Store) validateLoadedRecord(id string, record Record) error {
	if id != record.Request.ID {
		return errors.New("request map key mismatch")
	}
	requestCreated, createdErr := time.Parse(time.RFC3339, record.Request.CreatedAt)
	requestExpires, expiresErr := time.Parse(time.RFC3339, record.Request.ExpiresAt)
	if createdErr != nil || expiresErr != nil {
		return errors.New("invalid persisted request timestamps")
	}
	if err := model.ValidateRequest(record.Request, requestExpires.Add(-time.Second), s.requestMaxTTL); err != nil {
		return err
	}
	state := "pending"
	var previousReceiptCreated time.Time
	for _, receipt := range record.Receipts {
		if err := model.VerifyReceiptSignature(receipt, s.publicKey); err != nil {
			return err
		}
		receiptCreated, createdErr := time.Parse(time.RFC3339, receipt.CreatedAt)
		receiptExpires, expiresErr := time.Parse(time.RFC3339, receipt.ExpiresAt)
		if createdErr != nil || expiresErr != nil {
			return errors.New("invalid persisted receipt timestamps")
		}
		if err := model.ValidateReceipt(receipt, receiptExpires.Add(-time.Second), s.receiptMaxTTL); err != nil {
			return err
		}
		if receiptCreated.Before(requestCreated) || !receiptCreated.Before(requestExpires) || (!previousReceiptCreated.IsZero() && receiptCreated.Before(previousReceiptCreated)) {
			return errors.New("persisted receipt timestamp falls outside the request lifetime")
		}
		if receipt.RequestID != id || receipt.RequestDigest != record.Request.Digest {
			return errors.New("persisted receipt binding mismatch")
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
		retainUntil := requestExpires.Add(s.receiptMaxTTL)
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
	return copy
}

func cloneMap(source map[string]string) map[string]string {
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}
