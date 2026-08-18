package trusted

import (
	"bytes"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/donovan-yohan/airlock/internal/model"
)

const (
	// maxExecutionOutputPreviewBytes bounds each independently captured stream,
	// both before and after sanitization. The final persisted value reserves
	// space for an explicit truncation marker.
	maxExecutionOutputPreviewBytes = 8 << 10
	outputTruncationMarker         = "\n[truncated: trusted local preview limit reached]"
	maxOutputContentBytes          = maxExecutionOutputPreviewBytes - len(outputTruncationMarker)
)

// ExecutionOutputPreview is trusted-local attempt evidence. It must never be
// copied into receipts, requester synchronization, MCP, Hermes, or logs.
type ExecutionOutputPreview struct {
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	Redacted        bool   `json:"redacted,omitempty"`
}

// boundedOutput acknowledges every write so a noisy child cannot block, but
// retains at most the raw per-stream budget. Sanitization happens at the sole
// durable-state boundary, which also covers injected test runners.
type boundedOutput struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	truncated bool
}

func (w *boundedOutput) Write(value []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := maxExecutionOutputPreviewBytes - w.buffer.Len()
	if remaining <= 0 {
		w.truncated = true
		return len(value), nil
	}
	if len(value) > remaining {
		_, _ = w.buffer.Write(value[:remaining])
		w.truncated = true
		return len(value), nil
	}
	_, _ = w.buffer.Write(value)
	return len(value), nil
}

func (w *boundedOutput) snapshot() (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.buffer.Bytes()), w.truncated
}

// sanitizeExecutionOutputPreview is the only conversion permitted before a
// preview enters durable state. It strips terminal control sequences and
// invisible/noncharacter runes before credential detection, so an ANSI or Cf
// split token is recognized in its deobfuscated form. The stored result is
// valid UTF-8, has no rendering controls other than newline/tab, and is always
// within the same byte budget used by validation after restart.
func sanitizeExecutionOutputPreview(preview ExecutionOutputPreview) ExecutionOutputPreview {
	stdout, stdoutTruncated, stdoutRedacted := sanitizeExecutionOutput([]byte(preview.Stdout), preview.StdoutTruncated)
	stderr, stderrTruncated, stderrRedacted := sanitizeExecutionOutput([]byte(preview.Stderr), preview.StderrTruncated)
	return ExecutionOutputPreview{
		Stdout: stdout, Stderr: stderr,
		StdoutTruncated: stdoutTruncated, StderrTruncated: stderrTruncated,
		Redacted: preview.Redacted || stdoutRedacted || stderrRedacted,
	}
}

func sanitizeExecutionOutput(raw []byte, truncated bool) (string, bool, bool) {
	var normalized strings.Builder
	normalized.Grow(min(len(raw), maxOutputContentBytes))
	for len(raw) > 0 {
		if raw[0] == 0x1b {
			raw = skipANSISequence(raw)
			continue
		}
		value, size := utf8.DecodeRune(raw)
		if value == utf8.RuneError && size == 1 {
			if !appendOutputFragment(&normalized, "\\x"+hexByte(raw[0])) {
				truncated = true
				break
			}
			raw = raw[1:]
			continue
		}
		raw = raw[size:]
		switch {
		case value == '\n' || value == '\t':
			if !appendOutputFragment(&normalized, string(value)) {
				truncated = true
			}
		case unicode.IsControl(value) || unicode.Is(unicode.Cf, value) || isOutputNoncharacter(value):
			// Stripping is deliberate: it makes the displayed and scanned text
			// agree, and avoids retaining bidi/invisible reviewer deception.
			continue
		default:
			if !appendOutputFragment(&normalized, string(value)) {
				truncated = true
			}
		}
		if truncated && normalized.Len() >= maxOutputContentBytes {
			break
		}
	}

	text, redacted := redactExecutionOutput(normalized.String())
	if len(text) > maxOutputContentBytes {
		text = truncateOutputUTF8(text, maxOutputContentBytes)
		truncated = true
	}
	if truncated {
		text += outputTruncationMarker
	}
	return text, truncated, redacted
}

// skipANSISequence strips the bounded ECMA-48 forms that commonly split
// visible text: CSI, OSC, and a single-character escape. Unterminated forms
// consume the remaining captured data rather than exposing terminal syntax.
func skipANSISequence(raw []byte) []byte {
	if len(raw) == 1 {
		return raw[1:]
	}
	switch raw[1] {
	case '[': // CSI: final byte is 0x40..0x7e.
		for index := 2; index < len(raw); index++ {
			if raw[index] >= 0x40 && raw[index] <= 0x7e {
				return raw[index+1:]
			}
		}
		return nil
	case ']': // OSC: BEL or ST (ESC \\) terminates it.
		for index := 2; index < len(raw); index++ {
			if raw[index] == 0x07 {
				return raw[index+1:]
			}
			if raw[index] == 0x1b && index+1 < len(raw) && raw[index+1] == '\\' {
				return raw[index+2:]
			}
		}
		return nil
	default:
		return raw[2:]
	}
}

func appendOutputFragment(builder *strings.Builder, fragment string) bool {
	if builder.Len()+len(fragment) > maxOutputContentBytes {
		return false
	}
	builder.WriteString(fragment)
	return true
}

func truncateOutputUTF8(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	end := 0
	for end < len(value) {
		_, size := utf8.DecodeRuneInString(value[end:])
		if end+size > maximum {
			break
		}
		end += size
	}
	return value[:end]
}

func redactExecutionOutput(value string) (string, bool) {
	redacted := model.RedactLikelyCredentials(value)
	changed := redacted != value
	for _, prefix := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"} {
		if next, didRedact := redactPrefixedOpaqueValue(redacted, prefix); didRedact {
			redacted, changed = next, true
		}
	}
	return redacted, changed
}

func redactPrefixedOpaqueValue(text, prefix string) (string, bool) {
	var result strings.Builder
	cursor := 0
	changed := false
	for {
		offset := strings.Index(text[cursor:], prefix)
		if offset < 0 {
			result.WriteString(text[cursor:])
			return result.String(), changed
		}
		index := cursor + offset
		result.WriteString(text[cursor:index])
		end := index + len(prefix)
		for end < len(text) && ((text[end] >= 'a' && text[end] <= 'z') || (text[end] >= 'A' && text[end] <= 'Z') || (text[end] >= '0' && text[end] <= '9') || text[end] == '_') {
			end++
		}
		if end-index >= len(prefix)+20 {
			result.WriteString("[REDACTED]")
			changed = true
			cursor = end
			continue
		}
		result.WriteString(prefix)
		cursor = index + len(prefix)
	}
}

func isOutputNoncharacter(value rune) bool {
	return (value >= 0xfdd0 && value <= 0xfdef) || (value <= unicode.MaxRune && value&0xfffe == 0xfffe)
}

func hexByte(value byte) string {
	const hex = "0123456789abcdef"
	return string([]byte{hex[value>>4], hex[value&15]})
}
