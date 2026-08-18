//go:build linux

package trusted

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestProductionLauncherRejectsIDMappedNobody(t *testing.T) {
	info, err := os.Stat("/usr/bin/bwrap")
	if err != nil {
		t.Skipf("bwrap unavailable: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("bwrap stat lacks Linux ownership metadata")
	}
	if stat.Uid != 65534 {
		t.Skipf("host does not expose bwrap as UID 65534 (uid=%d)", stat.Uid)
	}
	if _, err := computeRootOwnedExecutableSHA256("/usr/bin/bwrap"); err == nil {
		t.Fatal("production launcher verification accepted UID 65534")
	}
	if _, err := computeSandboxLauncherSHA256ForTest("/usr/bin/bwrap"); err != nil {
		t.Fatalf("internal rootless test seam lost non-writable launcher validation: %v", err)
	}
}

func TestGitHubCLIMustBeStaticBeforePlanning(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := computeExecutableSHA256(staticFakeGH(t, root)); err != nil {
		t.Fatalf("static fake gh rejected: %v", err)
	}
	if _, err := os.Stat("/usr/bin/bwrap"); err == nil {
		if _, err := computeExecutableSHA256("/usr/bin/bwrap"); err == nil {
			t.Fatal("dynamically linked bwrap was accepted as a minimal-runtime gh")
		}
	}
}

func TestHostsYAMLRejectsHostileSourceShapes(t *testing.T) {
	newConfig := func(t *testing.T) (string, string) {
		t.Helper()
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		configDir := filepath.Join(root, "config")
		if err := os.Mkdir(configDir, 0o700); err != nil {
			t.Fatal(err)
		}
		return root, configDir
	}
	for _, test := range []struct {
		name  string
		write func(*testing.T, string, string)
	}{
		{"symlink", func(t *testing.T, root, config string) {
			t.Helper()
			target := filepath.Join(root, "target")
			if err := os.WriteFile(target, []byte("github.example.invalid:\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(config, "hosts.yml")); err != nil {
				t.Fatal(err)
			}
		}},
		{"group-readable", func(t *testing.T, _, config string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(config, "hosts.yml"), []byte("github.example.invalid:\n"), 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized", func(t *testing.T, _, config string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(config, "hosts.yml"), bytes.Repeat([]byte{'x'}, maxHostsYAMLBytes+1), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"fifo", func(t *testing.T, _, config string) {
			t.Helper()
			if err := syscall.Mkfifo(filepath.Join(config, "hosts.yml"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, configDir := newConfig(t)
			test.write(t, root, configDir)
			if _, err := credentialSourceIdentity(configDir); err == nil {
				t.Fatal("hostile hosts.yml was accepted")
			}
		})
	}
}

func TestHostsYAMLRejectsParentSymlinkAndPinsOpenedSource(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	realParent := filepath.Join(root, "real")
	configDir := filepath.Join(realParent, "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("github.example.invalid:\n  user: original\n")
	if err := os.WriteFile(filepath.Join(configDir, "hosts.yml"), original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realParent, filepath.Join(root, "linked-parent")); err != nil {
		t.Fatal(err)
	}
	if _, err := credentialSourceIdentity(filepath.Join(root, "linked-parent", "config")); err == nil {
		t.Fatal("config directory through a symlink parent was accepted")
	}

	file, info, err := openHostsYAML(configDir)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	replacement := filepath.Join(configDir, "replacement")
	if err := os.WriteFile(replacement, []byte("github.example.invalid:\n  user: replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, filepath.Join(configDir, "hosts.yml")); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "snapshot")
	if _, err := snapshotOpenedFile(file, info, destination, "airlock-gh-hosts-yml/v1", maxHostsYAMLBytes, false); err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(copied, original) {
		t.Fatalf("opened hosts.yml was replaced through its pathname: %q %v", copied, err)
	}
}

func TestAnchoredConfigDirectorySurvivesNameReplacement(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(root, "config")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "hosts.yml"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	directory, err := openPrivateConfigDirectory(configDir)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := os.Rename(configDir, filepath.Join(root, "old-config")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "hosts.yml"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Openat(int(directory.Fd()), "hosts.yml", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "hosts.yml")
	defer file.Close()
	contents := make([]byte, len("original"))
	if _, err := file.Read(contents); err != nil || string(contents) != "original" {
		t.Fatalf("openat descriptor followed a replacement path: %q %v", contents, err)
	}
	if _, err := file.Stat(); err != nil {
		t.Fatalf("anchored descriptor was invalidated by name replacement: %v", err)
	}
}
