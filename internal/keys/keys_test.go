package keys

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGeneratedKeyPermissionsAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "trusted.key")
	publicPath := filepath.Join(dir, "trusted.pub")
	if err := GenerateFiles(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(privatePath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublic(publicPath); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		privateInfo, err := os.Stat(privatePath)
		if err != nil {
			t.Fatal(err)
		}
		if got := privateInfo.Mode().Perm(); got != 0o600 {
			t.Fatalf("private mode=%#o, want 0600", got)
		}
	}
	if err := GenerateFiles(privatePath, filepath.Join(dir, "other.pub")); err == nil {
		t.Fatal("keygen overwrote an existing private key")
	}
}

func TestOverlyPermissivePrivateKeyRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission assertion")
	}
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "trusted.key")
	publicPath := filepath.Join(dir, "trusted.pub")
	if err := GenerateFiles(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(privatePath); err == nil {
		t.Fatal("overly permissive private key accepted")
	}
}
