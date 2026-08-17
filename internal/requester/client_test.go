package requester

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/donovan-yohan/airlock/internal/model"
)

func TestParseLoopbackURLRejectsAuthorityExpansion(t *testing.T) {
	valid := []string{"http://127.0.0.1:8787", "http://[::1]:8787"}
	for _, raw := range valid {
		if _, err := ParseLoopbackURL(raw); err != nil {
			t.Fatalf("valid loopback URL rejected %q: %v", raw, err)
		}
	}
	invalid := []string{
		"https://127.0.0.1:8787", "http://localhost:8787", "http://127.0.0.1", "http://127.0.0.1:0",
		"http://user@127.0.0.1:8787", "http://127.0.0.1:8787/", "http://127.0.0.1:8787?next=x",
		"http://127.0.0.1:8787#fragment", "http://192.0.2.1:8787", "http://[::1]:bad",
	}
	for _, raw := range invalid {
		if _, err := ParseLoopbackURL(raw); err == nil {
			t.Fatalf("unsafe requester URL accepted %q", raw)
		}
	}
}

func TestClientRefusesRedirectAndEnvironmentProxy(t *testing.T) {
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1", http.StatusFound)
	}))
	defer redirect.Close()
	redirectClient, err := NewClient(redirect.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redirectClient.Capabilities(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("redirect error=%v, want unavailable", err)
	}

	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	catalog := clientTestCatalog(now)
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(catalog)
	}))
	defer direct.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	client, err := NewClient(direct.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	if _, err := client.Capabilities(context.Background()); err != nil {
		t.Fatalf("client inherited proxy environment: %v", err)
	}
}

func TestClientPreservesOnlySafeRequesterRejectionDetails(t *testing.T) {
	for _, test := range []struct {
		name       string
		detail     string
		wantDetail bool
	}{
		{"safe", "request rejected: requester request store is full", true},
		{"control", "unsafe\x1b[31m rejection", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": test.detail})
			}))
			defer server.Close()
			client, err := NewClient(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Create(context.Background(), CreateInput{})
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("rejection error=%v, want ErrRejected", err)
			}
			if got := strings.Contains(err.Error(), test.detail); got != test.wantDetail {
				t.Fatalf("rejection detail present=%v want=%v: %q", got, test.wantDetail, err)
			}
		})
	}
}

func TestClientRejectsFutureDataAndControlCursors(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	futureCatalog := clientTestCatalog(now.Add(10 * time.Minute))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/catalog":
			_ = json.NewEncoder(w).Encode(futureCatalog)
		case r.URL.Path == "/api/v1/requests" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"requests": []Record{}, "next_cursor": "bad\x1b[31m"})
		case r.URL.Path == "/api/v1/requests" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(clientTestRecord(t, now.Add(10*time.Minute)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	if _, err := client.Capabilities(context.Background()); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("future catalog error=%v, want invalid data", err)
	}
	if _, err := client.Records(context.Background(), 1, "bad\x1b[31m"); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("control cursor input error=%v, want invalid data", err)
	}
	if _, err := client.Records(context.Background(), 1, ""); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("control cursor response error=%v, want invalid data", err)
	}
	if _, err := client.Create(context.Background(), CreateInput{}); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("future request error=%v, want invalid data", err)
	}
}

func clientTestCatalog(now time.Time) model.Catalog {
	return model.Catalog{
		Version: model.CatalogVersion, IssuedAt: model.Timestamp(now.Add(-time.Minute)), ExpiresAt: model.Timestamp(now.Add(time.Hour)),
		Capabilities: []model.Capability{{
			ID: "github:example-owner", DisplayName: "GitHub",
			Actions:     []string{model.ActionGitHubAddCollaborator},
			Constraints: model.GitHubConstraints{Owner: "example-owner", Collaborator: "example-agent", Permissions: []string{"pull", "push"}},
		}},
	}
}

func clientTestRecord(t *testing.T, created time.Time) Record {
	t.Helper()
	request := model.Request{
		Version: model.RequestVersion, ID: "req_0123456789abcdefghij", CapabilityID: "github:example-owner", Action: model.ActionGitHubAddCollaborator, // pragma: allowlist secret
		Arguments: map[string]string{"repository": "project", "permission": "push"}, Reason: "bounded reason",
		CreatedAt: model.Timestamp(created), ExpiresAt: model.Timestamp(created.Add(time.Hour)), Nonce: "abcdefghijklmnopqrstuvwx",
	}
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	return Record{Request: request, State: "pending", Receipts: []model.Receipt{}}
}
