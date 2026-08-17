package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnexpectedServerReturnRunsOrderedShutdown(t *testing.T) {
	listenerError := errors.New("synthetic listener failure")
	stopped := make(chan struct{})
	err := serveUntilSignal(&http.Server{}, failingListener{err: listenerError}, nil, func(context.Context) {
		close(stopped)
	})
	if !errors.Is(err, listenerError) {
		t.Fatalf("serve error=%v", err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("unexpected server return skipped shutdown hook")
	}
}

type failingListener struct{ err error }

func (listener failingListener) Accept() (net.Conn, error) { return nil, listener.err }
func (failingListener) Close() error                       { return nil }
func (failingListener) Addr() net.Addr                     { return testAddr("failure") }

type testAddr string

func (addr testAddr) Network() string { return "test" }
func (addr testAddr) String() string  { return string(addr) }

func TestMCPCommandRegistersToolsWhileRequesterIsDown(t *testing.T) {
	originalInput, originalOutput := os.Stdin, os.Stdout
	inputReader, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outputReader, outputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Stdin, os.Stdout = originalInput, originalOutput
		_ = inputReader.Close()
		_ = outputReader.Close()
	}()
	os.Stdin, os.Stdout = inputReader, outputWriter
	if _, err := io.WriteString(inputWriter, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n"); err != nil {
		t.Fatal(err)
	}
	if err := inputWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"mcp", "--requester-url", "http://127.0.0.1:1"}); err != nil {
		t.Fatalf("offline MCP startup failed: %v", err)
	}
	if err := outputWriter.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(outputReader)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"airlock_capabilities", "airlock_create_request", "airlock_requests"} {
		if !strings.Contains(string(output), name) {
			t.Fatalf("MCP command did not register %q: %s", name, output)
		}
	}
}

func TestTrustedCLIRequiresRunningDaemonAndNeverFallsBackToStateOrGH(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "trusted-state")
	marker := filepath.Join(dir, "provider-invoked")
	configPath := filepath.Join(dir, "trusted.json")
	config := `{
  "listen":"127.0.0.1:8788",
  "state_dir":"` + stateDir + `",
  "control_socket":"` + filepath.Join(stateDir, "control.sock") + `",
  "private_key_file":"` + filepath.Join(dir, "trusted.key") + `",
  "requester_url":"http://127.0.0.1:8787",
  "github_cli_path":"` + marker + `",
  "github_config_dir":"` + filepath.Join(dir, "gh-config") + `",
  "execution_timeout":"30s",
  "poll_interval":"2s",
  "request_max_ttl":"15m",
  "catalog_ttl":"1h",
  "receipt_ttl":"1h",
  "allowed_logins":["reviewer@example.invalid"],
  "capabilities":[{"id":"github:example-owner","display_name":"Example GitHub authority","adapter":"github.repo.add_collaborator/v1","owner":"example-owner","collaborator":"example-agent","permissions":["pull"]}]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"trusted", "request", "execute", "--config", configPath, "--id", "req_0123456789abcdefghij"})
	if err == nil || !strings.Contains(err.Error(), "trusted daemon is unavailable") {
		t.Fatalf("missing daemon error=%v", err)
	}
	err = run([]string{"trusted", "requests", "list", "--config", configPath, "--cursor", "not-a-cursor"})
	if err == nil || !strings.Contains(err.Error(), "trusted control cursor is invalid") {
		t.Fatalf("invalid list cursor error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "trusted-state.json")); !os.IsNotExist(err) {
		t.Fatalf("CLI touched daemon-owned state: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("CLI invoked configured provider executable: %v", err)
	}
}

func TestMCPCommandRejectsUnsafeRequesterURLs(t *testing.T) {
	for _, raw := range []string{"http://localhost:8787", "https://127.0.0.1:8787", "http://127.0.0.1:8787/path"} {
		if err := run([]string{"mcp", "--requester-url", raw}); err == nil {
			t.Fatalf("unsafe MCP requester URL accepted %q", raw)
		}
	}
}
