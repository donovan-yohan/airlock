package mcp

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/donovan-yohan/airlock/internal/model"
	"github.com/donovan-yohan/airlock/internal/requester"
)

// formatForTest drives the real stdio surface end to end.
func formatForTest(server *Server, input string) (string, error) {
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader(input), &output); err != nil {
		return "", err
	}
	return output.String(), nil
}

type toolListResponse struct {
	Result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	} `json:"result"`
}

type conformanceVector struct {
	Name         string         `json:"name"`
	Tool         string         `json:"tool"`
	Arguments    map[string]any `json:"arguments"`
	Fixture      string         `json:"fixture"`
	WantError    bool           `json:"want_error"`
	WantCode     string         `json:"want_code"`
	WantFragment string         `json:"want_fragment"`
}

func TestConformanceVectors(t *testing.T) {
	contents, err := os.ReadFile("testdata/conformance-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []conformanceVector
	if err := json.Unmarshal(contents, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			server := testMCPServer(t, vector.Fixture)
			arguments := maps.Clone(vector.Arguments)
			switch arguments["reason_fixture"] {
			case "oversized":
				arguments["reason"] = strings.Repeat("x", model.MaxReasonBytes+1)
			case "control":
				arguments["reason"] = "line\nbreak"
			case "secret":
				arguments["reason"] = "password=correct-horse-battery-staple" // pragma: allowlist secret
			}
			delete(arguments, "reason_fixture")
			request := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": vector.Tool, "arguments": arguments}}
			line, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			output, err := formatForTest(server, string(line)+"\n")
			if err != nil {
				t.Fatal(err)
			}
			var response struct {
				Result struct {
					IsError           bool            `json:"isError"`
					StructuredContent json.RawMessage `json:"structuredContent"`
				} `json:"result"`
			}
			if err := json.Unmarshal([]byte(output), &response); err != nil {
				t.Fatalf("decode response: %v; output=%q", err, output)
			}
			if response.Result.IsError != vector.WantError {
				t.Fatalf("isError=%v want %v: %s", response.Result.IsError, vector.WantError, output)
			}
			if vector.WantCode != "" && !strings.Contains(string(response.Result.StructuredContent), `"code":"`+vector.WantCode+`"`) {
				t.Fatalf("missing error code %q: %s", vector.WantCode, output)
			}
			if vector.WantFragment != "" && !strings.Contains(output, vector.WantFragment) {
				t.Fatalf("missing result fragment %q: %s", vector.WantFragment, output)
			}
		})
	}
}

func TestMCPDiscoveryIsOfflineAndExact(t *testing.T) {
	client, err := requester.NewClient("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	server := New(client)
	if len(Instructions()) >= 2048 {
		t.Fatalf("instructions too long: %d", len(Instructions()))
	}
	for _, phrase := range []string{"untrusted data", "create and observe", "never execute", "executed", "external verification"} {
		if !strings.Contains(Instructions(), phrase) {
			t.Fatalf("instructions missing %q", phrase)
		}
	}
	input := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n" +
		"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n"
	output, err := formatForTest(server, input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, "requester_unavailable") {
		t.Fatalf("offline discovery contacted requester: %s", output)
	}
	var responses []toolListResponse
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		var response toolListResponse
		if err := json.Unmarshal([]byte(line), &response); err == nil && len(response.Result.Tools) != 0 {
			responses = append(responses, response)
		}
	}
	if len(responses) != 1 || len(responses[0].Result.Tools) != 3 {
		t.Fatalf("unexpected tool list: %s", output)
	}
	want := []string{"airlock_capabilities", "airlock_create_request", "airlock_requests"}
	for index, tool := range responses[0].Result.Tools {
		if tool.Name != want[index] {
			t.Fatalf("tool %d = %q, want %q", index, tool.Name, want[index])
		}
	}
}

func TestMCPRejectsProtocolAndNeverReturnsSensitiveCatalogFields(t *testing.T) {
	server := testMCPServer(t, "valid")
	for _, input := range []string{
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"airlock_capabilities\",\"arguments\":{\"extra\":true}}}\n",
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"airlock_create_request\",\"arguments\":null}}\n",
		"{\"jsonrpc\":\"2.0\",\"id\":{\"not\":\"an id\"},\"method\":\"tools/list\",\"params\":{}}\n",
		"{not json}\n",
	} {
		output, err := formatForTest(server, input)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output, "\"isError\":true") && !strings.Contains(output, "\"error\":") {
			t.Fatalf("invalid protocol/input accepted: %s", output)
		}
	}
	output, err := formatForTest(server, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"airlock_capabilities\",\"arguments\":{}}}\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"trusted-credential-canary", "gh api", "https://untrusted.invalid", "trusted_public_key", "signature"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("unsafe catalog field leaked %q: %s", forbidden, output)
		}
	}
}

func TestExpiredTerminalOutcomeAndReceiptHistoryRemainVisible(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	record := testRecord(t, now, true)
	record.State = "manually_executed"
	record.Receipts = append(record.Receipts, model.Receipt{
		Version:        model.ReceiptVersionV1,
		ID:             "rec_0123456789abcdefghik",
		RequestID:      record.Request.ID,
		RequestDigest:  record.Request.Digest,
		Decision:       model.DecisionExecute,
		Reviewer:       "reviewer@example.invalid",
		AdapterVersion: model.AdapterGitHubAddCollaboratorV1,
		CreatedAt:      model.Timestamp(now.Add(-4 * time.Minute)),
		ExpiresAt:      model.Timestamp(now.Add(-time.Minute)),
	})

	view := requestView(record, now)
	if view["fresh"] != false || view["effective_state"] != "manually_executed" || view["effect_status"] != "manual_execution_attested_external_verification_required" {
		t.Fatalf("terminal outcome was erased by expiry: %#v", view)
	}
	receipts, ok := view["receipts"].([]map[string]any)
	if !ok || len(receipts) != 2 {
		t.Fatalf("receipt history missing: %#v", view["receipts"])
	}
	for _, receipt := range receipts {
		if receipt["expired"] != true || receipt["decision"] == "" {
			t.Fatalf("receipt projection missing status: %#v", receipt)
		}
		for _, forbidden := range []string{"signature", "request_digest", "adapter_version", "url", "command"} {
			if _, exists := receipt[forbidden]; exists {
				t.Fatalf("receipt projection exposed %q: %#v", forbidden, receipt)
			}
		}
	}
}

func TestRequestViewRecognizesTrustedExecutionTerminalState(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	record := testRecord(t, now, false)
	record.State = "executed"
	request := record.Request
	record.Receipts = []model.Receipt{
		{Version: model.ReceiptVersion, ID: "rec_0123456789abcdefghij", RequestID: request.ID, RequestDigest: request.Digest, Decision: model.DecisionApproveForExecution, Reviewer: "reviewer@example.invalid", AdapterVersion: model.AdapterGitHubAddCollaboratorV1, CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(time.Hour))},
		{Version: model.ReceiptVersion, ID: "rec_0123456789abcdefghik", RequestID: request.ID, RequestDigest: request.Digest, Decision: model.DecisionExecuted, Reviewer: "reviewer@example.invalid", AdapterVersion: model.AdapterGitHubAddCollaboratorV1, CreatedAt: model.Timestamp(now.Add(time.Second)), ExpiresAt: model.Timestamp(now.Add(time.Hour))},
	}
	view := requestView(record, now)
	if view["effective_state"] != "executed" || view["effect_status"] != "trusted_execution_attested_external_verification_required" {
		t.Fatalf("trusted execution state was not surfaced: %#v", view)
	}
}

func testMCPServer(t *testing.T, fixture string) *Server {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	if fixture != "down" {
		catalog := testCatalog(now)
		record := testRecord(t, now, fixture == "expired")
		createdRecord := testRecord(t, now, false)
		handler = func(w http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/api/v1/catalog":
				_ = json.NewEncoder(w).Encode(catalog)
			case "/api/v1/requests":
				if request.Method == http.MethodPost {
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(createdRecord)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"requests": []requester.Record{record}})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}
	httpServer := httptest.NewServer(handler)
	t.Cleanup(httpServer.Close)
	client, err := requester.NewClient(httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	server := New(client)
	server.now = func() time.Time { return now }
	return server
}

// testCatalog is deliberately unsigned: the requester-side client holds no
// trust root, so the canary fields below must never be verified or returned.
func testCatalog(now time.Time) model.Catalog {
	return model.Catalog{
		Version: model.CatalogVersion, IssuedAt: model.Timestamp(now.Add(-time.Minute)), ExpiresAt: model.Timestamp(now.Add(time.Hour)),
		TrustedPublicKey: "trusted-credential-canary", Signature: "signature-canary",
		Capabilities: []model.Capability{{
			ID: "github:example-owner", DisplayName: "gh api https://untrusted.invalid",
			Actions:     []string{model.ActionGitHubAddCollaborator},
			Constraints: model.GitHubConstraints{Owner: "example-owner", Collaborator: "example-agent", Permissions: []string{"pull", "push"}},
		}},
	}
}

func testRecord(t *testing.T, now time.Time, expired bool) requester.Record {
	t.Helper()
	expires := now.Add(time.Hour)
	created := now
	if expired {
		expires = now.Add(-time.Minute)
		created = expires.Add(-10 * time.Minute)
	}
	request := model.Request{
		Version: model.RequestVersion, ID: "req_0123456789abcdefghij", CapabilityID: "github:example-owner", Action: model.ActionGitHubAddCollaborator, // pragma: allowlist secret
		Arguments: map[string]string{"repository": "project", "permission": "push"}, Reason: "bounded reason",
		CreatedAt: model.Timestamp(created), ExpiresAt: model.Timestamp(expires), Nonce: "abcdefghijklmnopqrstuvwx",
	}
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	if !expired {
		return requester.Record{Request: request, State: "pending", Receipts: []model.Receipt{}}
	}
	receipt := model.Receipt{
		Version: model.ReceiptVersionV1, ID: "rec_0123456789abcdefghij", RequestID: request.ID, RequestDigest: request.Digest,
		Decision: model.DecisionApprove, Reviewer: "reviewer@example.invalid", AdapterVersion: model.AdapterGitHubAddCollaboratorV1,
		CreatedAt: model.Timestamp(expires.Add(-5 * time.Minute)), ExpiresAt: model.Timestamp(expires),
	}
	return requester.Record{Request: request, State: "approved", Receipts: []model.Receipt{receipt}}
}
