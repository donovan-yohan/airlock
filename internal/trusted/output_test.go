package trusted

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

const testOutputCredential = "ghp_TESTOUTPUTREDACTIONCANARY0123456789" // pragma: allowlist secret

func TestExecutionOutputPreviewIsBoundedNormalizedAndRedactedBeforePersistence(t *testing.T) {
	// The credential is deliberately interrupted by both ANSI and invisible
	// Unicode. Normalization must remove those separators before redaction.
	raw := append([]byte("before\xff\x00\x1b[31mghp_\u200b"), []byte(strings.TrimPrefix(testOutputCredential, "ghp_"))...)
	raw = append(raw, []byte("\ufdd0after")...)
	preview := sanitizeExecutionOutputPreview(ExecutionOutputPreview{
		Stdout: string(raw),
		Stderr: "Authorization: Bearer " + testOutputCredential,
	})
	if !preview.Redacted || strings.Contains(preview.Stdout, testOutputCredential) || strings.Contains(preview.Stderr, testOutputCredential) || !strings.Contains(preview.Stdout, "[REDACTED]") || !strings.Contains(preview.Stderr, "[REDACTED]") {
		t.Fatalf("credential-shaped output survived normalization/redaction: %#v", preview)
	}
	for _, text := range []string{preview.Stdout, preview.Stderr} {
		if len(text) > maxExecutionOutputPreviewBytes || !utf8.ValidString(text) || containsUnsafePreviewRune(text) {
			t.Fatalf("stored preview is unsafe or exceeds its bound: %q", text)
		}
		if strings.Contains(text, "\x1b") || strings.Contains(text, "[31m") || strings.Contains(text, "\u200b") || strings.Contains(text, "\ufdd0") {
			t.Fatalf("terminal or invisible input survived trusted preview normalization: %q", text)
		}
	}
	if !strings.Contains(preview.Stdout, "\\xff") {
		t.Fatalf("invalid byte was not visibly represented: %q", preview.Stdout)
	}
}

func TestNoisyExecutionOutputStaysWithinDurableRestartBound(t *testing.T) {
	writer := &boundedOutput{}
	raw := bytes.Repeat([]byte{0xff}, maxExecutionOutputPreviewBytes+1)
	if written, err := writer.Write(raw); err != nil || written != len(raw) {
		t.Fatalf("bounded writer did not acknowledge noisy output: written=%d err=%v", written, err)
	}
	stdout, truncated := writer.snapshot()
	preview := sanitizeExecutionOutputPreview(ExecutionOutputPreview{Stdout: stdout, StdoutTruncated: truncated})
	if !preview.StdoutTruncated || len(preview.Stdout) > maxExecutionOutputPreviewBytes || !strings.HasSuffix(preview.Stdout, outputTruncationMarker) || !utf8.ValidString(preview.Stdout) {
		t.Fatalf("noisy binary output did not preserve its bounded/truncated contract: %#v", preview)
	}
	if containsUnsafePreviewRune(preview.Stdout) || !validExecutionOutputPreview(&preview) {
		t.Fatalf("bounded preview would be rejected after restart: %#v", preview)
	}
}

func TestSanitizedOutputPreviewSurvivesTrustedStateRestart(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	runner.preview = ExecutionOutputPreview{
		Stdout: string(append([]byte("\xff\x1b[31mghp_\u200c"), []byte(strings.TrimPrefix(testOutputCredential, "ghp_"))...)),
		Stderr: strings.Repeat("loud\x00", maxExecutionOutputPreviewBytes),
	}
	request := trustedTestRequest(t, now)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID)); err != nil {
		t.Fatal(err)
	}
	record, _, found := store.Record(request.ID)
	if !found || len(record.Attempts) != 1 || record.Attempts[0].OutputPreview == nil || !validExecutionOutputPreview(record.Attempts[0].OutputPreview) {
		t.Fatalf("unsafe preview reached trusted state: %#v", record)
	}
	if strings.Contains(record.Attempts[0].OutputPreview.Stdout, testOutputCredential) || !record.Attempts[0].OutputPreview.Redacted || !record.Attempts[0].OutputPreview.StderrTruncated {
		t.Fatalf("stored output did not redact/truncate as expected: %#v", record.Attempts[0].OutputPreview)
	}
	restarted, err := NewStore(filepath.Dir(store.path), privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, *store.execution)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, found = restarted.Record(request.ID); !found {
		t.Fatal("sanitized output preview was rejected during trusted-state restart")
	}
}

func containsUnsafePreviewRune(value string) bool {
	for _, character := range value {
		if (unicode.IsControl(character) && character != '\n' && character != '\t') || unicode.Is(unicode.Cf, character) || isOutputNoncharacter(character) {
			return true
		}
	}
	return false
}
