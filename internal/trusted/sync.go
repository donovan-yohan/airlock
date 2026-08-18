package trusted

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/donovan-yohan/airlock/internal/config"
	"github.com/donovan-yohan/airlock/internal/httpjson"
	"github.com/donovan-yohan/airlock/internal/jsonstrict"
	"github.com/donovan-yohan/airlock/internal/model"
	"github.com/donovan-yohan/airlock/internal/netguard"
	"github.com/donovan-yohan/airlock/internal/paging"
)

const (
	maxSyncResponseBytes = 2 << 20
	maxPullPageRecords   = 16
	// Before command requests, requester state admitted up to 4096 compact
	// legacy records. Keep pagination finite without stranding a valid backlog
	// that predates the lower current admission cap.
	maxPersistedPullRecords = 4096
	maxPullPages            = (maxPersistedPullRecords + maxPullPageRecords - 1) / maxPullPageRecords
)

type Syncer struct {
	mu           sync.Mutex
	store        *Store
	privateKey   ed25519.PrivateKey
	capabilities []config.TrustedCapability
	requesterURL string
	pollInterval time.Duration
	catalogTTL   time.Duration
	client       *http.Client
	now          func() time.Time
	catalog      *model.Catalog
	pullCursor   string
	pullPages    int
}

func NewSyncer(store *Store, privateKey ed25519.PrivateKey, capabilities []config.TrustedCapability, requesterURL string, pollInterval, catalogTTL time.Duration) *Syncer {
	return &Syncer{
		store: store, privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		capabilities: append([]config.TrustedCapability(nil), capabilities...),
		requesterURL: strings.TrimSuffix(requesterURL, "/"), pollInterval: pollInterval,
		catalogTTL: catalogTTL, now: time.Now,
		client: netguard.OutboundClient(true),
	}
}

func (s *Syncer) Run(ctx context.Context, logger *log.Logger) {
	s.runOnceLogged(ctx, logger)
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOnceLogged(ctx, logger)
		}
	}
}

func (s *Syncer) SyncOnce(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var failures []error
	if err := s.publishCatalog(ctx); err != nil {
		failures = append(failures, fmt.Errorf("publish catalog: %w", err))
	}
	if err := s.pullRequests(ctx); err != nil {
		failures = append(failures, fmt.Errorf("pull requests: %w", err))
	}
	if err := s.deliverReceipts(ctx); err != nil {
		failures = append(failures, fmt.Errorf("deliver receipts: %w", err))
	}
	return errors.Join(failures...)
}

func (s *Syncer) runOnceLogged(ctx context.Context, logger *log.Logger) {
	if err := s.SyncOnce(ctx); err != nil {
		logger.Printf("trusted sync failed: %v", err)
	}
}

func (s *Syncer) publishCatalog(ctx context.Context) error {
	now := s.now().UTC()
	if s.catalog == nil || catalogNeedsRefresh(*s.catalog, now, s.catalogTTL) {
		capabilities := make([]model.Capability, 0, len(s.capabilities))
		for _, local := range s.capabilities {
			capabilities = append(capabilities, local.CatalogCapability())
		}
		catalog := model.Catalog{
			Version: model.CatalogVersion, IssuedAt: model.Timestamp(now),
			ExpiresAt: model.Timestamp(now.Add(s.catalogTTL)), Capabilities: capabilities,
		}
		if s.store.execution == nil {
			return errors.New("command profile execution is not configured")
		}
		catalog.Profiles = []model.CommandProfile{s.store.execution.Profile}
		if err := model.SignCatalog(&catalog, s.privateKey); err != nil {
			return err
		}
		s.catalog = &catalog
	}
	return s.postJSON(ctx, "/api/v1/catalog", s.catalog)
}

func (s *Syncer) pullRequests(ctx context.Context) error {
	query := url.Values{"limit": []string{fmt.Sprint(maxPullPageRecords)}}
	if s.pullCursor != "" {
		query.Set("cursor", s.pullCursor)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.requesterURL+"/api/v1/pending-requests?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("requester returned HTTP %d", response.StatusCode)
	}
	var payload struct {
		Requests   []model.Request `json:"requests"`
		NextCursor string          `json:"next_cursor,omitempty"`
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSyncResponseBytes+1))
	if err != nil || len(body) > maxSyncResponseBytes {
		return errors.New("requester response exceeds the size limit")
	}
	if err := jsonstrict.DecodeOne(body, &payload); err != nil {
		return errors.New("requester returned invalid request JSON")
	}
	if err := s.validatePullPage(payload.Requests, payload.NextCursor); err != nil {
		return errors.New("requester returned an invalid pending request page")
	}
	var rejected int
	for _, request := range payload.Requests {
		if err := s.store.Ingest(request); err != nil {
			rejected++
		}
	}
	// Advance only after the whole bounded page was decoded and considered.
	// Rejected records are retried after the cursor completes a full cycle.
	s.pullCursor = payload.NextCursor
	if s.pullCursor == "" {
		s.pullPages = 0
	} else {
		s.pullPages++
	}
	s.store.sweep()
	if rejected > 0 {
		return fmt.Errorf("%d requester records failed local validation", rejected)
	}
	return nil
}

func (s *Syncer) validatePullPage(requests []model.Request, nextCursor string) error {
	keys := make([]paging.Key, 0, len(requests))
	for _, request := range requests {
		createdAt, err := time.Parse(time.RFC3339, request.CreatedAt)
		if err != nil {
			return err
		}
		keys = append(keys, paging.Key{ID: request.ID, CreatedAt: createdAt})
	}
	if err := paging.ValidatePage(keys, maxPullPageRecords, s.pullCursor, nextCursor); err != nil {
		return err
	}
	if nextCursor != "" && s.pullPages+1 >= maxPullPages {
		return errors.New("requester pending request pagination exceeded its bound")
	}
	return nil
}

func (s *Syncer) deliverReceipts(ctx context.Context) error {
	var failures int
	for _, receipt := range s.store.Undelivered() {
		if err := s.postJSON(ctx, "/api/v1/receipts", receipt); err != nil {
			failures++
			continue
		}
		if err := s.store.MarkDelivered(receipt.ID); err != nil {
			failures++
		}
	}
	if failures != 0 {
		return fmt.Errorf("%d receipt deliveries failed", failures)
	}
	return nil
}

func (s *Syncer) postJSON(ctx context.Context, path string, value any) error {
	body, err := httpjson.Marshal(value)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.requesterURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("requester returned HTTP %d", response.StatusCode)
	}
	return nil
}

func catalogNeedsRefresh(catalog model.Catalog, now time.Time, ttl time.Duration) bool {
	issued, issuedErr := time.Parse(time.RFC3339, catalog.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339, catalog.ExpiresAt)
	if issuedErr != nil || expiresErr != nil {
		return true
	}
	refreshAt := issued.Add(ttl / 2)
	return !now.Before(refreshAt) || !expires.After(now)
}
