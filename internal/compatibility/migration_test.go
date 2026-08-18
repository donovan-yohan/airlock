// Package compatibility_test keeps the command-broker migration boundary
// auditable from the public requester/trusted store contracts.
package compatibility_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/donovan-yohan/airlock/internal/config"
	"github.com/donovan-yohan/airlock/internal/model"
	"github.com/donovan-yohan/airlock/internal/requester"
	"github.com/donovan-yohan/airlock/internal/trusted"
)

// These fixture shapes intentionally mirror the durable v1/v2 files rather
// than creating records through current store methods. That proves current
// readers keep historical records readable without claiming old binaries can
// represent a command record.
type requesterStateFixture struct {
	Catalog  *model.Catalog              `json:"catalog,omitempty"`
	Requests map[string]requester.Record `json:"requests"`
}

type trustedStateFixture struct {
	Requests map[string]trusted.Record `json:"requests"`
}

const legacyTrustedConfigFixture = `{
  "listen":"127.0.0.1:8788", "state_dir":"state", "control_socket":"state/control.sock",
  "private_key_file":"trusted.key", "requester_url":"https://requester-node.example.invalid",
  "github_cli_path":"/usr/bin/gh", "github_config_dir":"gh-config", "execution_timeout":"30s",
  "poll_interval":"2s", "request_max_ttl":"15m", "catalog_ttl":"1h", "receipt_ttl":"24h",
  "allowed_logins":["reviewer@example.invalid"], "capabilities":[]
}`

func TestCommandBrokerMigrationCompatibilityMatrix(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)

	t.Run("current strict config rejects base trusted configuration", func(t *testing.T) {
		path := filepath.Join(privateDir(t), "trusted.json")
		writeFixture(t, path, json.RawMessage(legacyTrustedConfigFixture))
		if _, err := config.LoadTrusted(path); err == nil {
			t.Fatal("current binary accepted base trusted config without command-broker fields")
		}
	})

	t.Run("base-format requester state into current", func(t *testing.T) {
		dir := privateDir(t)
		manualRequest := legacyRequest(t, now, "req_0123456789abcdefghij")
		manual := requester.Record{Request: manualRequest, State: model.DecisionManuallyExecuted, Receipts: []model.Receipt{
			legacyReceipt(t, privateKey, manualRequest, model.ReceiptVersionV1, model.DecisionApproveForManualExecution, "rec_0123456789abcdefghij", now),
			legacyReceipt(t, privateKey, manualRequest, model.ReceiptVersionV1, model.DecisionManuallyExecuted, "rec_0123456789abcdefghik", now.Add(time.Second)),
		}}
		writeFixture(t, filepath.Join(dir, "requester-state.json"), requesterStateFixture{
			Catalog: legacyCatalog(t, privateKey, now), Requests: map[string]requester.Record{manualRequest.ID: manual},
		})
		store, err := requester.NewStore(dir, publicKey, time.Hour, time.Hour, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		recovered, found := store.Record(manualRequest.ID)
		if !found || recovered.State != model.DecisionManuallyExecuted || len(recovered.Receipts) != 2 {
			t.Fatalf("current requester did not recover base state: %#v", recovered)
		}
	})

	t.Run("base-format trusted state into current", func(t *testing.T) {
		dir := privateDir(t)
		manualRequest := legacyRequest(t, now, "req_0123456789abcdefghik")
		writeFixture(t, filepath.Join(dir, "trusted-state.json"), trustedStateFixture{Requests: map[string]trusted.Record{
			manualRequest.ID: {
				Request: manualRequest, State: model.DecisionManuallyExecuted,
				Receipts: []trusted.Delivery{
					{Receipt: legacyReceipt(t, privateKey, manualRequest, model.ReceiptVersionV1, model.DecisionApproveForManualExecution, "rec_0123456789abcdefghil", now)},
					{Receipt: legacyReceipt(t, privateKey, manualRequest, model.ReceiptVersionV1, model.DecisionManuallyExecuted, "rec_0123456789abcdefghim", now.Add(time.Second))},
				},
			},
		}})
		store, err := trusted.NewStore(dir, privateKey, legacyCapabilities(), time.Hour, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		recovered, _, found := store.Record(manualRequest.ID)
		if !found || recovered.State != model.DecisionManuallyExecuted || len(recovered.Receipts) != 2 {
			t.Fatalf("current trusted node did not recover base state: %#v", recovered)
		}
	})

	t.Run("current requester with legacy trusted catalog fails closed", func(t *testing.T) {
		store, err := requester.NewStore(privateDir(t), publicKey, time.Hour, time.Hour, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.ImportCatalog(*legacyCatalog(t, privateKey, now)); err != nil {
			t.Fatal(err)
		}
		_, err = store.Create(commandInput())
		if err == nil || !strings.Contains(err.Error(), "does not support command proposals") {
			t.Fatalf("legacy trusted catalog accepted a current proposal: %v", err)
		}
	})

	t.Run("current trusted node accepts legacy requester records", func(t *testing.T) {
		dir := privateDir(t)
		request := legacyRequest(t, now, "req_0123456789abcdefghil")
		writeFixture(t, filepath.Join(dir, "trusted-state.json"), trustedStateFixture{Requests: map[string]trusted.Record{
			request.ID: {Request: request, State: "pending", Receipts: []trusted.Delivery{}},
		}})
		store, err := trusted.NewStore(dir, privateKey, legacyCapabilities(), time.Hour, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if record, _, found := store.Record(request.ID); !found || record.Request.Version != model.RequestVersionV1 || record.State != "pending" {
			t.Fatalf("legacy requester record was not retained: %#v", record)
		}
	})

	t.Run("historical v1 manual and v2 execution receipts remain readable", func(t *testing.T) {
		dir := privateDir(t)
		manualRequest := legacyRequest(t, now, "req_0123456789abcdefghim")
		executedRequest := legacyRequest(t, now, "req_0123456789abcdefghin")
		fixture := requesterStateFixture{Catalog: legacyCatalog(t, privateKey, now), Requests: map[string]requester.Record{
			manualRequest.ID: {Request: manualRequest, State: model.DecisionManuallyExecuted, Receipts: []model.Receipt{
				legacyReceipt(t, privateKey, manualRequest, model.ReceiptVersionV1, model.DecisionApproveForManualExecution, "rec_0123456789abcdefghio", now),
				legacyReceipt(t, privateKey, manualRequest, model.ReceiptVersionV1, model.DecisionManuallyExecuted, "rec_0123456789abcdefghip", now.Add(time.Second)),
			}},
			executedRequest.ID: {Request: executedRequest, State: model.DecisionExecuted, Receipts: []model.Receipt{
				legacyReceipt(t, privateKey, executedRequest, model.ReceiptVersionV2, model.DecisionApproveForExecution, "rec_0123456789abcdefghiq", now),
				legacyReceipt(t, privateKey, executedRequest, model.ReceiptVersionV2, model.DecisionExecuted, "rec_0123456789abcdefghir", now.Add(time.Second)),
			}},
		}}
		writeFixture(t, filepath.Join(dir, "requester-state.json"), fixture)
		store, err := requester.NewStore(dir, publicKey, time.Hour, time.Hour, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		for id, state := range map[string]string{manualRequest.ID: model.DecisionManuallyExecuted, executedRequest.ID: model.DecisionExecuted} {
			record, found := store.Record(id)
			if !found || record.State != state || len(record.Receipts) != 2 {
				t.Fatalf("historical receipt fixture %s was not recovered: %#v", id, record)
			}
		}
	})

	t.Run("current command records exist only in current state", func(t *testing.T) {
		dir := privateDir(t)
		store, err := requester.NewStore(dir, publicKey, time.Hour, time.Hour, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.ImportCatalog(currentCatalog(t, privateKey, now)); err != nil {
			t.Fatal(err)
		}
		created, err := store.Create(commandInput())
		if err != nil {
			t.Fatal(err)
		}
		recovered, err := requester.NewStore(dir, publicKey, time.Hour, time.Hour, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		record, found := recovered.Record(created.Request.ID)
		if !found || record.Request.Version != model.RequestVersion || len(record.Request.Argv) == 0 {
			t.Fatalf("current command record was not retained: %#v", record)
		}
		// Old binaries are deliberately not invoked here: their strict state
		// decoder cannot represent this record. The rollback test restores the
		// pre-upgrade full config+state checkpoint instead of projecting it.
	})
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeFixture(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func legacyCapabilities() []config.TrustedCapability {
	return []config.TrustedCapability{{
		ID: "github:example-owner", DisplayName: "Example GitHub authority", Adapter: model.AdapterGitHubAddCollaboratorV1,
		Owner: "example-owner", Collaborator: "example-agent", Permissions: []string{"pull", "push"},
	}}
}

func legacyCatalog(t *testing.T, key ed25519.PrivateKey, now time.Time) *model.Catalog {
	t.Helper()
	catalog := &model.Catalog{
		Version: model.CatalogVersionV1, IssuedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(30 * time.Minute)),
		Capabilities: []model.Capability{legacyCapabilities()[0].CatalogCapability()},
	}
	if err := model.SignCatalog(catalog, key); err != nil {
		t.Fatal(err)
	}
	return catalog
}

func currentCatalog(t *testing.T, key ed25519.PrivateKey, now time.Time) model.Catalog {
	t.Helper()
	catalog := model.Catalog{
		Version: model.CatalogVersion, IssuedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(30 * time.Minute)),
		Profiles: []model.CommandProfile{{
			ID: model.ProfileGitHubCommandID, Version: model.ProfileGitHubCommandVersion, DisplayName: "GitHub CLI command",
			AuthorityLabel: "Broad GitHub authority", SandboxLabel: "Ephemeral local state", NetworkLabel: "GitHub network",
			CWDLabel: "Ephemeral directory", OutputLabel: "Trusted-only preview",
			Limits: model.ProfileLimits{MaxArgvCount: model.MaxArgvCount, MaxArgumentBytes: model.MaxArgumentBytes, MaxAggregateBytes: model.MaxArgvAggregateBytes},
		}},
		Capabilities: []model.Capability{legacyCapabilities()[0].CatalogCapability()},
	}
	if err := model.SignCatalog(&catalog, key); err != nil {
		t.Fatal(err)
	}
	return catalog
}

func commandInput() requester.CreateInput {
	return requester.CreateInput{
		ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion,
		Argv: []string{"api", "repos/example-owner/project"}, Reason: "Compatibility fixture", TTLSeconds: 600,
	}
}

func legacyRequest(t *testing.T, now time.Time, id string) model.Request {
	t.Helper()
	request := model.Request{
		Version: model.RequestVersionV1, ID: id, CapabilityID: "github:example-owner", Action: model.ActionGitHubAddCollaborator,
		Arguments: map[string]string{"repository": "project", "permission": "push"}, Reason: "Historical compatibility fixture",
		CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(20 * time.Minute)), Nonce: "0123456789abcdefghijklmnopqrstuv",
	}
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	return request
}

func legacyReceipt(t *testing.T, key ed25519.PrivateKey, request model.Request, version, decision, id string, created time.Time) model.Receipt {
	t.Helper()
	receipt := model.Receipt{
		Version: version, ID: id, RequestID: request.ID, RequestDigest: request.Digest, Decision: decision,
		Reviewer: "reviewer@example.invalid", AdapterVersion: model.AdapterGitHubAddCollaboratorV1,
		CreatedAt: model.Timestamp(created), ExpiresAt: model.Timestamp(created.Add(time.Hour)),
	}
	if err := model.SignReceipt(&receipt, key); err != nil {
		t.Fatal(err)
	}
	return receipt
}
