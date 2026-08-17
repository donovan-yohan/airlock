package statefile

import (
	"os"
	"path/filepath"
	"runtime"
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
