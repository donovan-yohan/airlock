package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
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
	for _, phrase := range []string{"untrusted data", "propose and observe", "never execute", "executed", "verify provider state"} {
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

func TestMCPRejectsDuplicateProposalFields(t *testing.T) {
	server := testMCPServer(t, "current")
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"airlock_create_request","arguments":{"profile_id":"github.command","profile_version":"v1","argv":["api","user"],"argv":["auth","token"],"reason":"review exact argv","ttl_seconds":600}}}` + "\n"
	output, err := formatForTest(server, input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, `"code":-32600`) {
		t.Fatalf("ambiguous MCP proposal was not rejected at the protocol boundary: %s", output)
	}
}

func TestMCPRejectsCredentialAndInvisibleArgvBeforeRequesterEgress(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeRequester{created: testRecord(t, now, false)}
	server := newServer(fake)
	server.now = func() time.Time { return now }
	for _, test := range []struct {
		name string
		argv string
	}{
		{"credential", "Authorization: Bearer " + strings.Repeat("a", 20)},
		{"invisible", "safe\u200bvalue"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"airlock_create_request","arguments":{"profile_id":"github.command","profile_version":"v1","argv":["api",%q],"reason":"review exact argv","ttl_seconds":600}}}`, test.argv)
			output, err := formatForTest(server, input+"\n")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output, `"isError":true`) {
				t.Fatalf("unsafe argv accepted through MCP: %s", test.name)
			}
			if strings.Contains(output, test.argv) {
				t.Fatal("unsafe argv appeared in MCP response")
			}
		})
	}
	if fake.createCalls != 0 {
		t.Fatal("unsafe MCP argv reached requester client")
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

func TestMCPRequestPagesStayWithinFramingBudget(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	records := make([]requester.Record, maxMCPRecordPage)
	for index := range records {
		record := testRecord(t, now, false)
		record.Request.ID = fmt.Sprintf("req_%020d", index)
		record.Request.Digest = strings.Repeat("a", 64)
		record.Request.Argv = make([]string, model.MaxArgvCount)
		for argvIndex := range record.Request.Argv {
			record.Request.Argv[argvIndex] = strings.Repeat(`"`, model.MaxArgvAggregateBytes/model.MaxArgvCount)
		}
		record.Request.Reason = strings.Repeat(`"`, model.MaxReasonBytes)
		record.Receipts = make([]model.Receipt, 5)
		for receiptIndex := range record.Receipts {
			record.Receipts[receiptIndex] = model.Receipt{
				ID: fmt.Sprintf("rec_%020d", index*5+receiptIndex), Decision: model.DecisionApproveForExecution,
				Reviewer: strings.Repeat(`"`, 254), PlanDigest: strings.Repeat("b", 64),
				CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(time.Hour)),
			}
		}
		records[index] = record
	}
	fake := &fakeRequester{records: records}
	server := newServer(fake)
	server.now = func() time.Time { return now }
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"airlock_requests","arguments":{}}}` + "\n"
	output, err := formatForTest(server, input)
	if err != nil || strings.Contains(output, `"isError":true`) || fake.recordsLimit != maxMCPRecordPage || len(output) > maxMessageBytes {
		t.Fatalf("bounded default page limit=%d bytes=%d err=%v output=%s", fake.recordsLimit, len(output), err, output)
	}
	t.Logf("maximum MCP request page bytes=%d", len(output))
	oversized := fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"airlock_requests","arguments":{"limit":%d}}}`, maxMCPRecordPage+1) + "\n"
	output, err = formatForTest(server, oversized)
	if err != nil || !strings.Contains(output, `"isError":true`) {
		t.Fatalf("oversized MCP page accepted: err=%v output=%s", err, output)
	}
	properties := toolDefinitions[2].InputSchema["properties"].(map[string]any)
	limit := properties["limit"].(map[string]any)
	if limit["maximum"] != maxMCPRecordPage {
		t.Fatalf("request tool schema maximum=%v", limit["maximum"])
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
		{Version: model.ReceiptVersion, ID: "rec_0123456789abcdefghij", RequestID: request.ID, RequestDigest: request.Digest, Decision: model.DecisionApproveForExecution, Reviewer: "reviewer@example.invalid", ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion, PlanDigest: strings.Repeat("b", 64), CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(time.Hour))},
		{Version: model.ReceiptVersion, ID: "rec_0123456789abcdefghik", RequestID: request.ID, RequestDigest: request.Digest, Decision: model.DecisionExecuted, Reviewer: "reviewer@example.invalid", ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion, PlanDigest: strings.Repeat("b", 64), CreatedAt: model.Timestamp(now.Add(time.Second)), ExpiresAt: model.Timestamp(now.Add(time.Hour))},
	}
	view := requestView(record, now)
	if view["effective_state"] != "executed" || view["effect_status"] != "trusted_execution_attested_external_verification_required" {
		t.Fatalf("trusted execution state was not surfaced: %#v", view)
	}
}

func testMCPServer(t *testing.T, fixture string) *Server {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeRequester{err: requester.ErrUnavailable}
	if fixture != "down" {
		fake = &fakeRequester{catalog: testCatalog(now), record: testRecord(t, now, fixture == "expired"), created: testRecord(t, now, false)}
	}
	server := newServer(fake)
	server.now = func() time.Time { return now }
	return server
}

type fakeRequester struct {
	catalog      model.Catalog
	record       requester.Record
	records      []requester.Record
	created      requester.Record
	err          error
	createCalls  int
	recordsLimit int
}

func (f *fakeRequester) Capabilities(context.Context) (model.Catalog, error) {
	return f.catalog, f.err
}

func (f *fakeRequester) Create(_ context.Context, input requester.CreateInput) (requester.Record, error) {
	f.createCalls++
	return f.created, f.err
}

func (f *fakeRequester) Records(_ context.Context, limit int, _ string) (requester.Page, error) {
	f.recordsLimit = limit
	if f.records != nil {
		return requester.Page{Records: append([]requester.Record(nil), f.records...)}, f.err
	}
	return requester.Page{Records: []requester.Record{f.record}}, f.err
}

// testCatalog is deliberately unsigned: the requester-side client holds no
// trust root, so the canary fields below must never be verified or returned.
func testCatalog(now time.Time) model.Catalog {
	return model.Catalog{
		Version: model.CatalogVersion, IssuedAt: model.Timestamp(now.Add(-time.Minute)), ExpiresAt: model.Timestamp(now.Add(time.Hour)),
		TrustedPublicKey: "trusted-credential-canary", Signature: "signature-canary",
		Profiles: []model.CommandProfile{{ID: model.ProfileGitHubCommandID, Version: model.ProfileGitHubCommandVersion, DisplayName: "GitHub CLI command", AuthorityLabel: "Broad GitHub authority", SandboxLabel: "Ephemeral private state", NetworkLabel: "GitHub network", CWDLabel: "Ephemeral directory", OutputLabel: "Bounded sanitized trusted-local output preview", Limits: model.ProfileLimits{MaxArgvCount: model.MaxArgvCount, MaxArgumentBytes: model.MaxArgumentBytes, MaxAggregateBytes: model.MaxArgvAggregateBytes}}},
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
		Version: model.RequestVersion, ID: "req_0123456789abcdefghij", ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion,
		Argv: []string{"api", "repos/example-owner/project"}, Reason: "bounded reason",
		CreatedAt: model.Timestamp(created), ExpiresAt: model.Timestamp(expires), Nonce: "abcdefghijklmnopqrstuvwx",
	}
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	if !expired {
		return requester.Record{Request: request, State: "pending", Receipts: []model.Receipt{}}
	}
	receipt := model.Receipt{
		Version: model.ReceiptVersion, ID: "rec_0123456789abcdefghij", RequestID: request.ID, RequestDigest: request.Digest,
		Decision: model.DecisionApproveForExecution, Reviewer: "reviewer@example.invalid", ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion, PlanDigest: strings.Repeat("b", 64),
		CreatedAt: model.Timestamp(expires.Add(-5 * time.Minute)), ExpiresAt: model.Timestamp(expires),
	}
	return requester.Record{Request: request, State: "approved_for_execution", Receipts: []model.Receipt{receipt}}
}
