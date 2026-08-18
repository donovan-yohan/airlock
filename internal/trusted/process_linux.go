//go:build linux

package trusted

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func runDirectCommand(ctx context.Context, plan ExecutionPlan, environment []string) (ExecutionOutputPreview, error) {
	stdout, stderr := &boundedOutput{}, &boundedOutput{}
	launcher := plan.runtimeSandboxLauncher
	gh := plan.runtimeExecutable
	if launcher == "" || gh == "" || plan.runtimeWorkingDirectory == "" {
		return ExecutionOutputPreview{}, errors.New("private sandbox invocation is unavailable")
	}
	root := filepath.Dir(filepath.Dir(gh))
	configDir := filepath.Join(root, "gh-config")
	arguments := bubblewrapArguments(gh, configDir, plan.runtimeWorkingDirectory, environment, plan.Argv)
	command := exec.CommandContext(ctx, launcher, arguments...)
	// The launcher is invoked by its already-pinned absolute path. It needs only
	// PATH before bubblewrap replaces its environment with the reviewed policy.
	command.Env = []string{"PATH=/airlock/bin"}
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	command.WaitDelay = 2 * time.Second
	err := command.Run()
	stdoutText, stdoutTruncated := stdout.snapshot()
	stderrText, stderrTruncated := stderr.snapshot()
	return ExecutionOutputPreview{Stdout: stdoutText, Stderr: stderrText, StdoutTruncated: stdoutTruncated, StderrTruncated: stderrTruncated}, err
}

// bubblewrapArguments intentionally has no requester-controlled path, env,
// cwd, launcher, or option. Network remains shared so gh can reach GitHub;
// this is namespace/filesystem confinement, not an egress firewall.
func bubblewrapArguments(gh, configDir, workDir string, environment, argv []string) []string {
	arguments := []string{
		"--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--share-net",
		"--clearenv", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/run",
		"--dir", "/airlock", "--dir", "/airlock/bin", "--dir", "/airlock/home", "--dir", "/airlock/home/.config", "--dir", "/airlock/home/.local", "--dir", "/airlock/home/.cache", "--dir", "/airlock/work",
		"--dir", "/etc", "--dir", "/etc/ssl",
		"--ro-bind", gh, "/airlock/bin/gh", "--ro-bind", configDir, "/airlock/home/.config/gh", "--bind", workDir, "/airlock/work",
	}
	// gh is statically linked in the supported deployment. Do not bind broad
	// host trees such as /usr, /bin, /lib, or /etc just to make arbitrary
	// configured binaries work. This explicit surface is the CA and DNS data
	// GitHub network access needs; it excludes homes, Airlock state, sockets,
	// aliases, extensions, and all canonical gh configuration.
	for _, path := range []string{"/etc/ssl/certs", "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"} {
		if info, err := os.Stat(path); err == nil && (info.IsDir() || info.Mode().IsRegular()) {
			arguments = append(arguments, "--ro-bind", path, path)
		}
	}
	for _, value := range environment {
		key, content, found := splitEnvironment(value)
		if found {
			arguments = append(arguments, "--setenv", key, content)
		}
	}
	arguments = append(arguments, "--chdir", "/airlock/work", "--", "/airlock/bin/gh")
	return append(arguments, argv...)
}

func splitEnvironment(value string) (string, string, bool) {
	for index := range value {
		if value[index] == '=' {
			return value[:index], value[index+1:], index != 0
		}
	}
	return "", "", false
}
