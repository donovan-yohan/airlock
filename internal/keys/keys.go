package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxKeyFileBytes = 1024

func GenerateFiles(privatePath, publicPath string) error {
	if privatePath == "" || publicPath == "" || privatePath == publicPath {
		return errors.New("distinct private and public key paths are required")
	}
	if err := os.MkdirAll(filepath.Dir(privatePath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(publicPath), 0o700); err != nil {
		return err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privateEncoded := base64.RawStdEncoding.EncodeToString(privateKey) + "\n"
	publicEncoded := base64.RawStdEncoding.EncodeToString(publicKey) + "\n"
	if err := writeExclusive(privatePath, []byte(privateEncoded), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := writeExclusive(publicPath, []byte(publicEncoded), 0o644); err != nil {
		_ = os.Remove(privatePath)
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	raw, err := readKey(path, true)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key file")
	}
	return ed25519.PrivateKey(decoded), nil
}

func LoadPublic(path string) (ed25519.PublicKey, error) {
	raw, err := readKey(path, false)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key file")
	}
	return ed25519.PublicKey(decoded), nil
}

func readKey(path string, private bool) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("key file must be a regular file")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("private key file must be accessible only by its owner")
	}
	if !private && info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("public key file must not be group- or world-writable")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxKeyFileBytes {
		return "", errors.New("key file exceeds size limit")
	}
	return strings.TrimSpace(string(b)), nil
}

func writeExclusive(path string, contents []byte, permissions os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, permissions)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := f.Chmod(permissions); err != nil {
		return err
	}
	if _, err := io.Copy(f, bytes.NewReader(contents)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
