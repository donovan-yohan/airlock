package trusted

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	maxExecutableBytes = 256 << 20
	maxHostsYAMLBytes  = 1 << 20
)

// openedRegular is deliberately backed by an already-open descriptor. Callers
// hash and copy that descriptor rather than checking a pathname then reopening
// it, which closes the replace-after-check window.
func openedRegular(path string, executable bool, requireRootOwner bool) (*os.File, os.FileInfo, error) {
	if requireRootOwner {
		return openSandboxLauncher(path, false)
	}
	file, err := openNoFollow(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open trusted source: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maxExecutableBytes || (executable && info.Mode().Perm()&0o111 == 0) {
		_ = file.Close()
		return nil, nil, errors.New("trusted source must be a bounded regular file with the required ownership and mode")
	}
	return file, info, nil
}

func digestOpenedFile(file *os.File, info os.FileInfo, domain string, limit int64) (string, error) {
	if info.Size() > limit {
		return "", errors.New("trusted source exceeds size limit")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, info.Size()); err != nil {
		return "", err
	}
	return hex.EncodeToString(sha256SumDomain(domain, hash.Sum(nil))), nil
}

func sha256SumDomain(domain string, contentHash []byte) []byte {
	hash := sha256.New()
	_, _ = io.WriteString(hash, domain)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(contentHash)
	return hash.Sum(nil)
}

func computeExecutableSHA256(path string) (string, error) {
	file, info, err := openedRegular(path, true, false)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if err := validateStaticGitHubCLI(file); err != nil {
		return "", err
	}
	return digestOpenedFile(file, info, "airlock-executable/v1", maxExecutableBytes)
}

func computeRootOwnedExecutableSHA256(path string) (string, error) {
	return computeSandboxLauncherSHA256(path, false)
}

// computeSandboxLauncherSHA256ForTest is an internal test seam for rootless
// CI images that project system-owned files as UID 65534. Production config
// never reaches it: NewStore verifies every configured launcher as UID 0.
func computeSandboxLauncherSHA256ForTest(path string) (string, error) {
	return computeSandboxLauncherSHA256(path, true)
}

// computeSandboxLauncherSHA256 reopens the canonical launcher with the same
// no-symlink, ownership, and permission checks used at startup. Callers use
// it immediately before reserving an invocation, so the plan remains bound to
// the path-keyed launcher the kernel will execute rather than a copied binary.
func computeSandboxLauncherSHA256(path string, testOnly bool) (string, error) {
	file, info, err := openSandboxLauncher(path, testOnly)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return digestOpenedFile(file, info, "airlock-sandbox-launcher/v1", maxExecutableBytes)
}

func credentialSourceIdentity(configDir string) (string, error) {
	file, info, err := openHostsYAML(configDir)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if info.Mode().Perm()&0o077 != 0 || info.Size() > maxHostsYAMLBytes {
		return "", errors.New("hosts.yml must be owner-private and bounded")
	}
	return digestOpenedFile(file, info, "airlock-gh-hosts-yml/v1", maxHostsYAMLBytes)
}

// snapshotOpenedFile copies and hashes an already opened source into a new
// private regular file. Its returned identity is of exactly those bytes.
func snapshotOpenedFile(file *os.File, info os.FileInfo, destination, domain string, limit int64, executable bool) (string, error) {
	if info.Size() > limit {
		return "", errors.New("trusted source exceeds size limit")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	before, err := file.Stat()
	if err != nil || !sameOpenedFile(info, before) {
		return "", errors.New("trusted source changed before snapshot")
	}
	mode := os.FileMode(0o600)
	if executable {
		mode = 0o700
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.CopyN(io.MultiWriter(output, hash), file, info.Size())
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	after, err := file.Stat()
	if err != nil || !sameOpenedFile(info, after) {
		return "", errors.New("trusted source changed during snapshot")
	}
	return hex.EncodeToString(sha256SumDomain(domain, hash.Sum(nil))), nil
}

func snapshotTrustedFile(source, destination, domain string, limit int64, executable, rootOwned bool) (string, error) {
	file, info, err := openedRegular(source, executable, rootOwned)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return snapshotOpenedFile(file, info, destination, domain, limit, executable)
}

func snapshotHostsYAML(configDir, destination string) (string, error) {
	file, info, err := openHostsYAML(configDir)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if info.Mode().Perm()&0o077 != 0 || info.Size() > maxHostsYAMLBytes {
		return "", errors.New("hosts.yml must be owner-private and bounded")
	}
	return snapshotOpenedFile(file, info, destination, "airlock-gh-hosts-yml/v1", maxHostsYAMLBytes, false)
}
