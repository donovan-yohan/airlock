package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCommandRequestCanonicalDigestBindsEveryProposalField(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	baseline := validRequest(now)
	baseline.Argv = []string{"api", "--method", "POST", "repos/example/project/issues", "-f", "title=a;b"}
	if err := SetRequestDigest(&baseline); err != nil {
		t.Fatal(err)
	}
	copy := baseline
	copy.Argv = append([]string(nil), baseline.Argv...)
	if err := SetRequestDigest(&copy); err != nil || copy.Digest != baseline.Digest {
		t.Fatalf("equivalent canonical proposal digest=%q err=%v", copy.Digest, err)
	}

	mutations := []struct {
		name string
		edit func(*Request)
	}{
		{"version", func(value *Request) { value.Version = RequestVersionV1 }},
		{"id", func(value *Request) { value.ID = "req_0123456789abcdefghik" }},
		{"profile id", func(value *Request) { value.ProfileID = ProfileShellRunID }},
		{"profile version", func(value *Request) { value.ProfileVersion = "v2" }},
		{"argv value", func(value *Request) { value.Argv[2] = "PUT" }},
		{"argv order", func(value *Request) { value.Argv[0], value.Argv[1] = value.Argv[1], value.Argv[0] }},
		{"reason", func(value *Request) { value.Reason = "changed reason" }},
		{"created", func(value *Request) { value.CreatedAt = Timestamp(now.Add(time.Second)) }},
		{"expires", func(value *Request) { value.ExpiresAt = Timestamp(now.Add(30 * time.Minute)) }},
		{"nonce", func(value *Request) { value.Nonce = "abcdefghijklmnopqrstuvwx" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := baseline
			changed.Argv = append([]string(nil), baseline.Argv...)
			mutation.edit(&changed)
			if err := VerifyRequestDigest(changed); err == nil {
				t.Fatal("mutated proposal retained the original digest")
			}
		})
	}
}

func TestCommandArgvRejectsAmbiguousTerminalTextAndBounds(t *testing.T) {
	hostile := []struct {
		name string
		argv []string
	}{
		{"empty list", nil},
		{"empty element", []string{"api", ""}},
		{"NUL", []string{"api", "bad\x00value"}},
		{"newline", []string{"api", "bad\nvalue"}},
		{"ANSI escape", []string{"api", "\x1b[31mdelete"}},
		{"C1 control", []string{"api", "\u009b31mdelete"}},
		{"bidi override", []string{"api", "safe\u202egnp.exe"}},
		{"zero width space", []string{"api", "safe\u200bvalue"}},
		{"zero width non-joiner", []string{"api", "safe\u200cvalue"}},
		{"zero width joiner", []string{"api", "safe\u200dvalue"}},
		{"byte order mark", []string{"api", "safe\ufeffvalue"}},
		{"Unicode noncharacter", []string{"api", "safe\ufdd0value"}},
		{"plane-end noncharacter", []string{"api", "safe\ufffevalue"}},
		{"GitHub token", []string{"api", "ghp_" + strings.Repeat("a", 24)}},
		{"Authorization header", []string{"api", "Authorization: Bearer " + strings.Repeat("a", 20)}},
		{"URL userinfo", []string{"api", "https://operator:password@example.invalid"}},
		{"labelled credential", []string{"api", "password=" + strings.Repeat("a", 12)}},
		{"invalid UTF-8", []string{"api", string([]byte{0xff, 0xfe})}},
		{"argument too large", []string{"api", strings.Repeat("x", MaxArgumentBytes+1)}},
		{"too many arguments", make([]string, MaxArgvCount+1)},
		{"aggregate too large", make([]string, MaxArgvCount)},
	}
	for index := range hostile[19].argv {
		hostile[19].argv[index] = "x"
	}
	for index := range hostile[20].argv {
		hostile[20].argv[index] = strings.Repeat("x", MaxArgumentBytes)
	}
	for _, test := range hostile {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateArgv(test.argv); err == nil {
				t.Fatalf("hostile argv accepted: %s", test.name)
			}
		})
	}

	ordinaryShellData := []string{"api", ";", "$(id)", "a && b", "*", "${HOME}"}
	if err := ValidateArgv(ordinaryShellData); err != nil {
		t.Fatalf("shell metacharacters were not treated as ordinary argv data: %v", err)
	}
}

func TestCurrentCommandDigestRefusesCredentialBeforeHashing(t *testing.T) {
	request := validRequest(time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC))
	request.Argv = []string{"api", "Authorization: Bearer " + strings.Repeat("a", 20)}
	request.Digest = "digest-must-not-change"
	if err := SetRequestDigest(&request); err == nil {
		t.Fatal("credential-shaped argv was canonicalized")
	}
	if request.Digest != "digest-must-not-change" {
		t.Fatal("credential-shaped argv changed request digest")
	}
}

func TestLegacyCanonicalBytesRemainStableAndDistinct(t *testing.T) {
	legacy := Request{
		Version: RequestVersionV1, ID: "req_0123456789abcdefghij", CapabilityID: "github:example-owner",
		Action: ActionGitHubAddCollaborator, Arguments: map[string]string{"permission": "push", "repository": "project"},
		Reason: "historical", CreatedAt: "2026-08-17T12:00:00Z", ExpiresAt: "2026-08-17T12:10:00Z",
		Nonce: "0123456789abcdefghijklmnopqrstuv",
	}
	encoded, err := RequestSigningBytes(legacy)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"airlock.request/v1","id":"req_0123456789abcdefghij","capability_id":"github:example-owner","action":"github.repo.add_collaborator","arguments":{"permission":"push","repository":"project"},"reason":"historical","created_at":"2026-08-17T12:00:00Z","expires_at":"2026-08-17T12:10:00Z","nonce":"0123456789abcdefghijklmnopqrstuv"}`
	if string(encoded) != want {
		t.Fatalf("legacy canonical bytes changed:\n got %s\nwant %s", encoded, want)
	}
	if !json.Valid(encoded) {
		t.Fatal("legacy canonical bytes are not JSON")
	}
	current := validRequest(time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC))
	currentBytes, err := RequestSigningBytes(current)
	if err != nil {
		t.Fatal(err)
	}
	if string(currentBytes) == string(encoded) || strings.Contains(string(currentBytes), "capability_id") {
		t.Fatalf("current request was silently reinterpreted as legacy: %s", currentBytes)
	}
}

func TestLegacyRequestWithInvisibleTextRemainsReadable(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	legacy := Request{
		Version: RequestVersionV1, ID: "req_0123456789abcdefghij", CapabilityID: "github:example-owner",
		Action: ActionGitHubAddCollaborator, Arguments: map[string]string{"permission": "push", "repository": "project"},
		Reason: "historical\u200b record", CreatedAt: Timestamp(now), ExpiresAt: Timestamp(now.Add(time.Hour)),
		Nonce: "0123456789abcdefghijklmnopqrstuv",
	}
	if err := SetRequestDigest(&legacy); err != nil {
		t.Fatalf("legacy digest: %v", err)
	}
	if err := ValidateRequest(legacy, now, time.Hour); err != nil {
		t.Fatalf("historical request readability changed: %v", err)
	}
}
