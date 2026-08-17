package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donovan-yohan/airlock/internal/model"
)

func TestExampleConfigsRemainValid(t *testing.T) {
	requester, err := LoadRequester(filepath.Join("..", "..", "configs", "requester.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if requester.Listen != "127.0.0.1:8787" {
		t.Fatalf("unexpected requester listener %q", requester.Listen)
	}
	trusted, err := LoadTrusted(filepath.Join("..", "..", "configs", "trusted.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(trusted.Capabilities) != 1 || trusted.Capabilities[0].Adapter != model.AdapterGitHubAddCollaboratorV1 {
		t.Fatalf("unexpected trusted capabilities: %#v", trusted.Capabilities)
	}
}

func TestDeploymentExamplesMatchDocumentedSystemdPaths(t *testing.T) {
	home := t.TempDir()
	configDir := filepath.Join(home, ".config", "airlock")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	copyExample := func(name string) string {
		t.Helper()
		contents, err := os.ReadFile(filepath.Join("..", "..", "configs", name+".example.json"))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(configDir, name+".json")
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	requester, err := LoadRequester(copyExample("requester"))
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := LoadTrusted(copyExample("trusted"))
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct{ field, got, want string }{
		{"requester.state_dir", requester.StateDir, filepath.Join(home, ".local", "state", "airlock", "requester")},
		{"requester.trusted_public_key_file", requester.TrustedPublicKeyFile, filepath.Join(configDir, "trusted.pub")},
		{"trusted.state_dir", trusted.StateDir, filepath.Join(home, ".local", "state", "airlock", "trusted")},
		{"trusted.private_key_file", trusted.PrivateKeyFile, filepath.Join(configDir, "trusted.key")},
	} {
		if check.got != check.want {
			t.Fatalf("deployment %s=%q want=%q", check.field, check.got, check.want)
		}
	}
	for _, role := range []string{"requester", "trusted"} {
		unit, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "airlock-"+role+".service"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(unit), "ReadWritePaths=%h/.local/state/airlock/"+role) {
			t.Fatalf("%s unit does not allow its configured state directory", role)
		}
	}
	deployment, err := os.ReadFile(filepath.Join("..", "..", "docs", "deployment.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"$HOME/.config/airlock/trusted.key", "$HOME/.config/airlock/trusted.pub", "$HOME/.local/state/airlock/requester", "$HOME/.local/state/airlock/trusted"} {
		if !strings.Contains(string(deployment), path) {
			t.Fatalf("deployment guide omits %q", path)
		}
	}
}

func TestConfigRejectsUnknownFieldsAndURLCredentials(t *testing.T) {
	dir := t.TempDir()
	unknownPath := filepath.Join(dir, "unknown.json")
	unknown := []byte(`{
  "listen":"127.0.0.1:1",
  "state_dir":"state",
  "trusted_public_key_file":"trusted.pub",
  "surprise":"value"
}`)
	if err := os.WriteFile(unknownPath, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRequester(unknownPath); err == nil {
		t.Fatal("unknown config field accepted")
	}
	if err := validateRequesterURL("https://user@example.invalid"); err == nil {
		t.Fatal("requester URL credentials accepted")
	}
	if err := validateRequesterURL("https://example.invalid/path"); err == nil {
		t.Fatal("requester URL path accepted")
	}
}

func TestTrustedConfigAcceptsConfiguredAuthorityIdentities(t *testing.T) {
	examplePath := filepath.Join("..", "..", "configs", "trusted.example.json")
	example, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	contents := bytes.ReplaceAll(example, []byte("example-owner"), []byte("other-owner"))
	contents = bytes.ReplaceAll(contents, []byte("example-agent"), []byte("other-user"))
	path := filepath.Join(t.TempDir(), "trusted.json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	trusted, err := LoadTrusted(path)
	if err != nil {
		t.Fatal(err)
	}
	capability := trusted.Capabilities[0]
	if capability.Owner != "other-owner" || capability.Collaborator != "other-user" {
		t.Fatalf("configured identities were not preserved: %#v", capability)
	}
}

func TestTrustedConfigRejectsInvalidAuthorityIdentities(t *testing.T) {
	examplePath := filepath.Join("..", "..", "configs", "trusted.example.json")
	example, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	tests := [][]byte{
		bytes.Replace(example, []byte(`"owner": "example-owner"`), []byte(`"owner": "-bad-owner"`), 1),
		bytes.Replace(example, []byte(`"collaborator": "example-agent"`), []byte(`"collaborator": "bad_user"`), 1),
		bytes.Replace(example, []byte(`"id": "github:example-owner"`), []byte(`"id": "github:other-owner"`), 1),
	}
	for index, contents := range tests {
		path := filepath.Join(t.TempDir(), "trusted.json")
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTrusted(path); err == nil {
			t.Fatalf("invalid authority identity %d accepted", index)
		}
	}
}
