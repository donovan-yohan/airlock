package statefile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/donovan-yohan/airlock/internal/jsonstrict"
)

const maxStateBytes = 16 << 20

// ErrTooLarge is returned when a durable snapshot cannot fit within the
// atomic state-file contract. Callers may map this capacity condition to a
// retryable service response without exposing storage internals.
var ErrTooLarge = errors.New("state file exceeds the size limit")

func Load(path string, destination any) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&0o077 != 0 {
		return errors.New("state file must be regular and accessible only by its owner")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return err
	}
	if len(b) > maxStateBytes {
		return ErrTooLarge
	}
	if err := jsonstrict.DecodeOne(b, destination); err != nil {
		return fmt.Errorf("decode state: %w", err)
	}
	return nil
}

func Save(path string, value any) error {
	dir := filepath.Dir(path)
	if err := EnsurePrivateDir(dir); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return err
	}
	b := encoded.Bytes()
	if len(b) > maxStateBytes {
		return ErrTooLarge
	}
	temporary, err := os.CreateTemp(dir, ".airlock-state-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(b); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	committed = true
	return directory.Sync()
}

// EnsurePrivateDir creates or verifies a real owner-private directory. Trusted
// daemon sockets use the same guard as atomic state files; on Linux, their
// listener separately verifies each peer credential before serving HTTP.
func EnsurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("state directory must be a private real directory")
	}
	return nil
}
