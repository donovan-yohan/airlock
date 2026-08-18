//go:build linux

package trusted

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// validateStaticGitHubCLI keeps the mounted runtime surface explicit. The
// supported gh package is a static Linux ELF, so a dynamically linked binary
// is rejected before a review can reserve execution for dependencies that the
// sandbox deliberately does not mount.
func validateStaticGitHubCLI(file *os.File) error {
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}
	image, err := elf.NewFile(file)
	if err != nil {
		return errors.New("github cli must be a static Linux ELF executable")
	}
	defer image.Close()
	for _, program := range image.Progs {
		if program.Type == elf.PT_INTERP {
			return errors.New("github cli must be statically linked for the minimal sandbox runtime")
		}
	}
	return nil
}

func openNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// openSandboxLauncher walks every component with openat(O_NOFOLLOW), so the
// opened launcher and its parents are the objects that were validated. A
// production launcher must be rooted in UID 0, non-writable directories and
// itself be a non-writable UID 0 regular executable. The test-only branch
// deliberately retains the non-writable/no-symlink checks while allowing an
// id-mapped rootfs to expose system files as UID 65534.
func openSandboxLauncher(path string, testOnly bool) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, nil, errors.New("sandbox launcher path must be clean and absolute")
	}
	rootFD, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	current := os.NewFile(uintptr(rootFD), "/")
	defer current.Close()
	if err := validateLauncherDirectory(current, testOnly); err != nil {
		return nil, nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, component := range parts[:len(parts)-1] {
		fd, err := syscall.Openat(int(current.Fd()), component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("open sandbox launcher parent: %w", err)
		}
		next := os.NewFile(uintptr(fd), component)
		if err := validateLauncherDirectory(next, testOnly); err != nil {
			_ = next.Close()
			return nil, nil, err
		}
		_ = current.Close()
		current = next
	}
	fd, err := syscall.Openat(int(current.Fd()), parts[len(parts)-1], syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open sandbox launcher: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if err := validateLauncherFile(info, testOnly); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, info, nil
}

func validateLauncherDirectory(file *os.File, testOnly bool) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || (!testOnly && stat.Uid != 0) {
		return errors.New("sandbox launcher parent must be a non-writable UID 0 directory")
	}
	return nil
}

func validateLauncherFile(info os.FileInfo, testOnly bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxExecutableBytes || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 || (!testOnly && stat.Uid != 0) {
		return errors.New("sandbox launcher must be a bounded non-writable UID 0 regular executable")
	}
	return nil
}

func openHostsYAML(configDir string) (*os.File, os.FileInfo, error) {
	directory, err := openPrivateConfigDirectory(configDir)
	if err != nil {
		return nil, nil, err
	}
	defer directory.Close()
	fd, err := syscall.Openat(int(directory.Fd()), "hosts.yml", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open hosts.yml: %w", err)
	}
	file := os.NewFile(uintptr(fd), "hosts.yml")
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maxHostsYAMLBytes || info.Mode().Perm()&0o077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		_ = file.Close()
		return nil, nil, errors.New("hosts.yml must be an owner-private bounded regular file")
	}
	return file, info, nil
}

func openPrivateConfigDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("GitHub config directory must be clean and absolute")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		nextFD, err := syscall.Openat(int(current.Fd()), component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("open GitHub config directory: %w", err)
		}
		next := os.NewFile(uintptr(nextFD), component)
		_ = current.Close()
		current = next
	}
	info, err := current.Stat()
	if err != nil {
		_ = current.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		_ = current.Close()
		return nil, errors.New("GitHub config directory must be an owner-private real directory")
	}
	return current, nil
}

func sameOpenedFile(first, second os.FileInfo) bool {
	left, leftOK := first.Sys().(*syscall.Stat_t)
	right, rightOK := second.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && left.Dev == right.Dev && left.Ino == right.Ino && first.Size() == second.Size() && first.Mode() == second.Mode() && left.Uid == right.Uid && left.Gid == right.Gid
}
