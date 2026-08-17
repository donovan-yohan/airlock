package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

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

func TestMCPCommandRejectsUnsafeRequesterURLs(t *testing.T) {
	for _, raw := range []string{"http://localhost:8787", "https://127.0.0.1:8787", "http://127.0.0.1:8787/path"} {
		if err := run([]string{"mcp", "--requester-url", raw}); err == nil {
			t.Fatalf("unsafe MCP requester URL accepted %q", raw)
		}
	}
}
