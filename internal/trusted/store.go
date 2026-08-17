package trusted

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/donovan-yohan/airlock/internal/config"
	"github.com/donovan-yohan/airlock/internal/model"
	"github.com/donovan-yohan/airlock/internal/paging"
	"github.com/donovan-yohan/airlock/internal/statefile"
)

type Delivery struct {
	Receipt   model.Receipt `json:"receipt"`
	Delivered bool          `json:"delivered"`
}

type Record struct {
	Request  model.Request `json:"request"`
	State    string        `json:"state"`
	Receipts []Delivery    `json:"receipts"`
}

type persistedState struct {
	Requests map[string]Record `json:"requests"`
}

type Store struct {
	mu            sync.RWMutex
	path          string
	privateKey    ed25519.PrivateKey
	capabilities  []config.TrustedCapability
	requestMaxTTL time.Duration
	receiptTTL    time.Duration
	now           func() time.Time
	state         persistedState
}

func NewStore(stateDir string, privateKey ed25519.PrivateKey, capabilities []config.TrustedCapability, requestMaxTTL, receiptTTL time.Duration) (*Store, error) {
	store := &Store{
		path: filepath.Join(stateDir, "trusted-state.json"), privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		capabilities: append([]config.TrustedCapability(nil), capabilities...), requestMaxTTL: requestMaxTTL,
		receiptTTL: receiptTTL, now: time.Now, state: persistedState{Requests: map[string]Record{}},
	}
	if err := statefile.Load(store.path, &store.state); err != nil {
		return nil, err
	}
	if store.state.Requests == nil {
		store.state.Requests = map[string]Record{}
	}
	changed := store.sanitizeLoaded()
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

func (s *Store) Ingest(request model.Request) error {
	now := s.now().UTC()
	if _, _, err := validateAndRender(request, s.capabilities, now, s.requestMaxTTL); err != nil {
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
	record := Record{Request: cloneRequest(request), State: "pending", Receipts: []Delivery{}}
	next := clonePersistedState(s.state)
	next.Requests[request.ID] = record
	if err := s.commit(next); err != nil {
		return err
	}
	return nil
}

// The serialized worst case remains below the shared 16 MiB state-file limit.
// Once full, ingest fails closed while existing decisions and deliveries remain
// writable.
const maxTrustedRequests = 4096

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
	return state == model.DecisionDeny || state == model.DecisionExecute
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

func (s *Store) Decide(id, decision, reviewer string) (model.Receipt, error) {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	record, found := s.state.Requests[id]
	if !found {
		return model.Receipt{}, errors.New("request not found")
	}
	_, adapterVersion, err := validateAndRender(record.Request, s.capabilities, now, s.requestMaxTTL)
	if err != nil {
		return model.Receipt{}, fmt.Errorf("request is no longer actionable: %w", err)
	}
	next, err := model.NextRequestState(record.State, decision)
	if err != nil {
		return model.Receipt{}, err
	}
	receiptID, err := model.NewRandom("rec_", 18)
	if err != nil {
		return model.Receipt{}, err
	}
	receipt := model.Receipt{
		Version: model.ReceiptVersion, ID: receiptID, RequestID: record.Request.ID,
		RequestDigest: record.Request.Digest, Decision: decision, Reviewer: reviewer,
		AdapterVersion: adapterVersion, CreatedAt: model.Timestamp(now),
		ExpiresAt: model.Timestamp(now.Add(s.receiptTTL)),
	}
	if err := model.ValidateReceipt(receipt, now, s.receiptTTL); err != nil {
		return model.Receipt{}, err
	}
	if err := model.SignReceipt(&receipt, s.privateKey); err != nil {
		return model.Receipt{}, err
	}
	record.State = next
	record.Receipts = append(record.Receipts, Delivery{Receipt: receipt})
	nextState := clonePersistedState(s.state)
	nextState.Requests[id] = record
	if err := s.commit(nextState); err != nil {
		return model.Receipt{}, err
	}
	return receipt, nil
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
	sort.Slice(receipts, func(i, j int) bool {
		if receipts[i].CreatedAt == receipts[j].CreatedAt {
			return receipts[i].ID < receipts[j].ID
		}
		return receipts[i].CreatedAt < receipts[j].CreatedAt
	})
	return receipts
}

// RecordPage bounds the review UI's reads through the shared paging contract,
// so both nodes order and cursor identically.
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
	command, _, err := validateAndRender(record.Request, s.capabilities, actionTime(record.Request), s.requestMaxTTL)
	if err != nil {
		return cloneRecord(record), "", true
	}
	return cloneRecord(record), command, true
}

func (s *Store) sanitizeLoaded() bool {
	publicKey := s.privateKey.Public().(ed25519.PublicKey)
	changed := false
	for id, record := range s.state.Requests {
		if id != record.Request.ID {
			delete(s.state.Requests, id)
			changed = true
			continue
		}
		validationTime := actionTime(record.Request)
		if _, _, err := validateAndRender(record.Request, s.capabilities, validationTime, s.requestMaxTTL); err != nil {
			delete(s.state.Requests, id)
			changed = true
			continue
		}
		state := "pending"
		receiptsValid := true
		for _, delivery := range record.Receipts {
			receipt := delivery.Receipt
			receiptExpiry, err := time.Parse(time.RFC3339, receipt.ExpiresAt)
			if err != nil {
				delete(s.state.Requests, id)
				changed = true
				receiptsValid = false
				break
			}
			if err := model.ValidateReceipt(receipt, receiptExpiry.Add(-time.Second), s.receiptTTL); err != nil {
				delete(s.state.Requests, id)
				changed = true
				receiptsValid = false
				break
			}
			if err := model.VerifyReceiptSignature(receipt, publicKey); err != nil {
				delete(s.state.Requests, id)
				changed = true
				receiptsValid = false
				break
			}
			if receipt.RequestID != id || receipt.RequestDigest != record.Request.Digest {
				delete(s.state.Requests, id)
				changed = true
				receiptsValid = false
				break
			}
			state, err = model.NextRequestState(state, receipt.Decision)
			if err != nil {
				delete(s.state.Requests, id)
				changed = true
				receiptsValid = false
				break
			}
		}
		if !receiptsValid {
			continue
		}
		if state != record.State {
			delete(s.state.Requests, id)
			changed = true
			continue
		}
	}
	return changed
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
