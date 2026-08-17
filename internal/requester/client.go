package requester

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/donovan-yohan/airlock/internal/model"
	"github.com/donovan-yohan/airlock/internal/netguard"
	"github.com/donovan-yohan/airlock/internal/paging"
)

const maxClientResponseBytes = 1 << 20

var (
	ErrUnavailable = errors.New("requester unavailable")
	ErrRejected    = errors.New("requester rejected request")
	ErrInvalidData = errors.New("requester returned invalid data")

	errRequesterEndpoint = errors.New("requester URL must be an explicit HTTP loopback IP and port")
)

// Client is the only requester transport used by local harness integrations.
// Its endpoint is intentionally narrower than the trusted node's Tailnet URL:
// it permits one explicit HTTP loopback IP listener and fixed API paths only.
type Client struct {
	base   url.URL
	client *http.Client
	now    func() time.Time
}

// Page is an in-process result, never a wire shape; see recordPageResponse.
type Page struct {
	Records    []Record
	NextCursor string
}

func NewClient(rawURL string) (*Client, error) {
	base, err := ParseLoopbackURL(rawURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		base:   base,
		now:    time.Now,
		client: netguard.OutboundClient(false),
	}, nil
}

// ParseLoopbackURL accepts exactly an HTTP loopback IP literal plus a concrete
// port. It deliberately rejects paths and every URL component that could alter
// authority or endpoint selection.
func ParseLoopbackURL(rawURL string) (url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Host == "" {
		return url.URL{}, errRequesterEndpoint
	}
	// No component may carry endpoint selection beyond scheme, host, and port.
	if parsed.Opaque != "" || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return url.URL{}, errRequesterEndpoint
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || host == "" || port == "" {
		return url.URL{}, errRequesterEndpoint
	}
	ip := net.ParseIP(host)
	portNumber, portErr := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return url.URL{}, errRequesterEndpoint
	}
	return *parsed, nil
}

func (c *Client) Capabilities(ctx context.Context) (model.Catalog, error) {
	var catalog model.Catalog
	if err := c.getJSON(ctx, "/api/v1/catalog", nil, &catalog); err != nil {
		return model.Catalog{}, err
	}
	// Validate hostile catalog strings and structure without treating its expiry
	// as current. Freshness is derived separately by the caller.
	issued, issuedErr := time.Parse(time.RFC3339, catalog.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339, catalog.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || issued.After(c.now().UTC().Add(model.ClockSkew)) || model.ValidateCatalog(catalog, expires.Add(-time.Second), 24*time.Hour) != nil {
		return model.Catalog{}, ErrInvalidData
	}
	return catalog, nil
}

func (c *Client) Create(ctx context.Context, input CreateInput) (Record, error) {
	var record Record
	if err := c.postJSON(ctx, "/api/v1/requests", input, http.StatusCreated, &record); err != nil {
		return Record{}, err
	}
	if err := validateRecord(record, c.now().UTC()); err != nil {
		return Record{}, ErrInvalidData
	}
	return record, nil
}

func (c *Client) Records(ctx context.Context, limit int, cursor string) (Page, error) {
	if limit < 1 || limit > MaxRecordPage || !paging.ValidCursor(cursor) {
		return Page{}, ErrInvalidData
	}
	query := url.Values{"limit": []string{strconv.Itoa(limit)}}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	var wire recordPageResponse
	if err := c.getJSON(ctx, "/api/v1/requests", query, &wire); err != nil {
		return Page{}, err
	}
	// The response is never trusted; limit already satisfies MaxRecordPage.
	if len(wire.Requests) > limit || !paging.ValidCursor(wire.NextCursor) {
		return Page{}, ErrInvalidData
	}
	for _, record := range wire.Requests {
		if err := validateRecord(record, c.now().UTC()); err != nil {
			return Page{}, ErrInvalidData
		}
	}
	return Page{Records: wire.Requests, NextCursor: wire.NextCursor}, nil
}

func (c *Client) getJSON(ctx context.Context, path string, query url.Values, destination any) error {
	endpoint := c.base
	endpoint.Path = path
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return ErrInvalidData
	}
	return c.doJSON(request, http.StatusOK, destination)
}

func (c *Client) postJSON(ctx context.Context, path string, value any, expectedStatus int, destination any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return ErrInvalidData
	}
	endpoint := c.base
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return ErrInvalidData
	}
	request.Header.Set("Content-Type", "application/json")
	return c.doJSON(request, expectedStatus, destination)
}

func (c *Client) doJSON(request *http.Request, expectedStatus int, destination any) error {
	response, err := c.client.Do(request)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxClientResponseBytes+1))
	if readErr != nil || len(body) > maxClientResponseBytes {
		return ErrInvalidData
	}
	if response.StatusCode >= 500 {
		return ErrUnavailable
	}
	if response.StatusCode != expectedStatus {
		if response.StatusCode == http.StatusUnprocessableEntity || response.StatusCode == http.StatusBadRequest {
			return rejectedError(body)
		}
		return ErrInvalidData
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidData
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidData
	}
	return nil
}

func rejectedError(body []byte) error {
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Error == "" || len(payload.Error) > 300 || !utf8.ValidString(payload.Error) {
		return ErrRejected
	}
	for _, character := range payload.Error {
		if unicode.IsControl(character) {
			return ErrRejected
		}
	}
	return fmt.Errorf("%w: %s", ErrRejected, payload.Error)
}

func validateRecord(record Record, now time.Time) error {
	created, createdErr := time.Parse(time.RFC3339, record.Request.CreatedAt)
	expires, expiresErr := time.Parse(time.RFC3339, record.Request.ExpiresAt)
	if createdErr != nil || expiresErr != nil || created.After(now.Add(model.ClockSkew)) || model.ValidateRequest(record.Request, expires.Add(-time.Second), time.Hour) != nil {
		return errors.New("invalid request record")
	}
	state := "pending"
	var previousReceiptCreated time.Time
	var transitionErr error
	for _, receipt := range record.Receipts {
		receiptCreated, createdErr := time.Parse(time.RFC3339, receipt.CreatedAt)
		receiptExpires, expiresErr := time.Parse(time.RFC3339, receipt.ExpiresAt)
		if createdErr != nil || expiresErr != nil || receiptCreated.After(now.Add(model.ClockSkew)) || receiptCreated.Before(created) || !receiptCreated.Before(expires) || (!previousReceiptCreated.IsZero() && receiptCreated.Before(previousReceiptCreated)) || model.ValidateReceipt(receipt, receiptExpires.Add(-time.Second), 7*24*time.Hour) != nil || receipt.RequestID != record.Request.ID || receipt.RequestDigest != record.Request.Digest {
			return errors.New("invalid receipt record")
		}
		previousReceiptCreated = receiptCreated
		state, transitionErr = model.NextRequestState(state, receipt.Decision)
		if transitionErr != nil {
			return errors.New("invalid receipt transition")
		}
	}
	if record.State != state {
		return errors.New("invalid request state")
	}
	return nil
}
