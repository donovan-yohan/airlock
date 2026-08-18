package statefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSaveIsPrivateAndLoadRejectsPermissiveState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission assertion")
	}
	path := filepath.Join(t.TempDir(), "private", "state.json")
	value := struct {
		Value string `json:"value"`
	}{"safe"}
	if err := Save(path, value); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("state mode=%#o, want 0600", got)
	}
	var loaded struct {
		Value string `json:"value"`
	}
	if err := Load(path, &loaded); err != nil || loaded.Value != "safe" {
		t.Fatalf("load=%q err=%v", loaded.Value, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Load(path, &loaded); err == nil {
		t.Fatal("permissive state file accepted")
	}
}

func TestSaveUsesLiteralJSONAndRefusesActualOverLimitOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state.json")
	if err := Save(path, map[string]string{"argv": strings.Repeat("<>&", 1024)}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`\u003c`)) || bytes.Contains(raw, []byte(`\u003e`)) || bytes.Contains(raw, []byte(`\u0026`)) {
		t.Fatalf("state JSON used HTML escaping: %q", raw[:min(len(raw), 100)])
	}
	before := append([]byte(nil), raw...)
	if err := Save(path, map[string]string{"too_large": strings.Repeat("x", maxStateBytes)}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("actual over-limit state output error=%v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("over-limit save changed existing state: err=%v", err)
	}
}

func TestStateDirectorySymlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink assertion")
	}
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, linked); err != nil {
		t.Fatal(err)
	}
	if err := Save(filepath.Join(linked, "state.json"), map[string]string{"x": "y"}); err == nil {
		t.Fatal("symlinked state directory accepted")
	}
}

func TestLoadRejectsDuplicateStateFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"value":"first","value":"second"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var loaded struct {
		Value string `json:"value"`
	}
	if err := Load(path, &loaded); err == nil {
		t.Fatal("duplicate durable state field accepted")
	}
}
