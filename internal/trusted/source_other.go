//go:build !linux

package trusted

import "os"

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

func validateStaticGitHubCLI(file *os.File) error { return os.ErrPermission }

func openSandboxLauncher(path string, testOnly bool) (*os.File, os.FileInfo, error) {
	return nil, nil, os.ErrPermission
}

func openHostsYAML(configDir string) (*os.File, os.FileInfo, error) {
	return nil, nil, os.ErrPermission
}

func sameOpenedFile(first, second os.FileInfo) bool {
	return first.Mode() == second.Mode() && first.Size() == second.Size()
}
