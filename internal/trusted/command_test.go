package trusted

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/donovan-yohan/airlock/internal/model"
)

const (
	fakeGHOutputCanary = "ghp_FAKEOUTPUTMUSTNEVERPERSISTOREGRESS0123456789" // pragma: allowlist secret
)

func TestLinuxCancellationKillsDirectCommandProcessGroup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux trusted-runtime process-group contract")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(root, "bin")
	configDir := filepath.Join(root, "gh-config")
	workDir := filepath.Join(root, "work")
	for _, directory := range []string{binDir, configDir, workDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(configDir, "hosts.yml"), []byte("github.example.invalid:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gh := staticFakeGH(t, binDir)
	if err := os.Rename(gh, filepath.Join(binDir, "gh")); err != nil {
		t.Fatal(err)
	}
	launcher := "/usr/bin/bwrap"
	if _, err := os.Stat(launcher); err != nil {
		skipOrFailRealSandbox(t, "real bwrap unavailable: %v", err)
	}
	marker := filepath.Join(workDir, "descendant-marker")
	plan := ExecutionPlan{Argv: []string{"spawn", "/airlock/work/descendant-marker"}, runtimeWorkingDirectory: workDir, runtimeExecutable: filepath.Join(binDir, "gh"), runtimeSandboxLauncher: launcher}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	preview, err := runDirectCommand(ctx, plan, minimalChildEnvironment())
	if sandboxUnavailable(err, preview) {
		skipOrFailRealSandbox(t, "real bwrap/kernel namespaces unavailable: %s", preview.Stderr)
	}
	if err == nil {
		t.Fatal("timed-out process group returned success")
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("descendant escaped timeout process group: %v", err)
	}
}

func sandboxUnavailable(err error, preview ExecutionOutputPreview) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(preview.Stdout + "\n" + preview.Stderr)
	return strings.Contains(text, "operation not permitted") || strings.Contains(text, "permission denied") || strings.Contains(text, "user namespaces")
}

func skipOrFailRealSandbox(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

func TestGenericGitHubPlanDigestBindsProposalExecutableAndPolicy(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	request := currentCommandRequest(t, now, "req_0123456789abcdefghij", []string{"release", "create", "v1.2.3", ";", "$(id)"})
	configDir := t.TempDir()
	if err := os.Chmod(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "hosts.yml"), []byte("github.example.invalid:\n  user: test-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	execution := trustedTestExecutionConfig(configDir)
	first, err := resolveExecutionPlan(request, trustedTestCapabilities(), now, 15*time.Minute, &execution)
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolveExecutionPlan(request, trustedTestCapabilities(), now, 15*time.Minute, &execution)
	if err != nil || second.Digest != first.Digest {
		t.Fatalf("deterministic plan digest=%q err=%v", second.Digest, err)
	}
	if !slices.Equal(first.Argv, request.Argv) || first.ExecutableSHA256 != execution.ExecutableSHA256 {
		t.Fatalf("generic argv or executable identity changed: %#v", first)
	}

	mutations := []struct {
		name string
		edit func(*ExecutionConfig)
	}{
		{"executable path", func(value *ExecutionConfig) { value.GitHubCLIPath = "/trusted/fake/other-gh" }},
		{"executable identity", func(value *ExecutionConfig) { value.ExecutableSHA256 = strings.Repeat("b", 64) }},
		{"config version", func(value *ExecutionConfig) { value.ProfileConfigVersion = "test-v2" }},
		{"authority", func(value *ExecutionConfig) { value.Profile.AuthorityLabel = "Different broad authority" }},
		{"identity", func(value *ExecutionConfig) { value.ExecutionIdentity = "different trusted identity" }},
		{"sandbox", func(value *ExecutionConfig) { value.Profile.SandboxLabel = "different sandbox policy" }},
		{"network", func(value *ExecutionConfig) { value.Profile.NetworkLabel = "different network policy" }},
		{"cwd", func(value *ExecutionConfig) { value.Profile.CWDLabel = "different cwd policy" }},
		{"output", func(value *ExecutionConfig) { value.Profile.OutputLabel = "different output policy" }},
		{"timeout", func(value *ExecutionConfig) { value.Timeout = 2 * time.Minute }},
	}
	if err := os.WriteFile(filepath.Join(configDir, "hosts.yml"), []byte("github.example.invalid:\n  user: changed-test-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changedCredential, err := resolveExecutionPlan(request, trustedTestCapabilities(), now, 15*time.Minute, &execution)
	if err != nil || changedCredential.Digest == first.Digest {
		t.Fatalf("credential content identity did not alter reviewed plan: digest=%q err=%v", changedCredential.Digest, err)
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := execution
			mutation.edit(&changed)
			plan, err := resolveExecutionPlan(request, trustedTestCapabilities(), now, 15*time.Minute, &changed)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Digest == first.Digest {
				t.Fatal("execution-relevant trusted policy did not change the plan digest")
			}
		})
	}
	tampered := first
	tampered.Argv = append([]string(nil), first.Argv...)
	tampered.Argv[0] = "auth"
	if err := verifyExecutionPlanDigest(tampered); err == nil {
		t.Fatal("tampered immutable plan retained its digest")
	}
}

func TestGitHubRiskWarningsCoverObviousHighImpactShapes(t *testing.T) {
	shapes := [][]string{
		{"auth", "login"},
		{"api", "repos/example/project", "--method=DELETE"},
		{"pr", "merge", "42"},
		{"release", "create", "v1"},
		{"workflow", "run", "deploy.yml"},
		{"repo", "edit", "--visibility=public"},
		{"repo", "archive", "example/project"},
		{"repo", "rename", "new-name"},
		{"repo", "delete", "example/project"},
	}
	for _, argv := range shapes {
		if warnings := classifyGitHubRisk(argv); len(warnings) < 2 {
			t.Fatalf("obvious high-impact shape was not flagged: argv=%q warnings=%q", argv, warnings)
		}
	}
	if warnings := classifyGitHubRisk([]string{"api", "user"}); len(warnings) != 1 {
		t.Fatalf("read shape received unexpected specific warnings: %q", warnings)
	}
}

func TestEscapedConvenienceRenderingIsBoundedWithoutChangingExactArgv(t *testing.T) {
	argv := make([]string, 8)
	for index := range argv {
		argv[index] = strings.Repeat("\u0378", model.MaxArgumentBytes/3)
	}
	if err := model.ValidateArgv(argv); err != nil {
		t.Fatal(err)
	}
	plan := ExecutionPlan{Executable: "/trusted/fake/gh", Argv: argv}
	display := escapedCommand(plan)
	if len(display) > model.MaxDisplayBytes || !strings.Contains(display, "omitted") {
		t.Fatalf("oversized escaped rendering was not safely omitted: bytes=%d", len(display))
	}
	if !slices.Equal(plan.Argv, argv) {
		t.Fatal("display bounding mutated executable argv")
	}
}

func TestStaleShownPlanAndPostReservationConfigChangesCannotChangeInvocation(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	request := currentCommandRequest(t, now, "req_0123456789abcdefghij", []string{"api", "repos/example/project"})
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	shownDigest := trustedPlanDigest(t, store, request.ID)
	store.execution.ProfileConfigVersion = "test-v2"
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", shownDigest); err != ErrExecutionRejected {
		t.Fatalf("stale shown plan result=%v", err)
	}
	if runner.Calls() != 0 {
		t.Fatal("stale shown plan reached the child")
	}

	freshDigest := trustedPlanDigest(t, store, request.ID)
	runner.onRun = func() { store.execution.ProfileConfigVersion = "test-v3" }
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", freshDigest); err != nil {
		t.Fatal(err)
	}
	record, _, found := store.Record(request.ID)
	if !found || len(record.Attempts) != 1 || record.Attempts[0].Plan == nil {
		t.Fatalf("reserved plan missing: %#v", record)
	}
	if record.Attempts[0].Plan.ProfileConfigVersion != "test-v2" || record.Attempts[0].PlanDigest != freshDigest {
		t.Fatalf("invocation rederived changed config after approval: %#v", record.Attempts[0])
	}
	for _, delivery := range record.Receipts {
		if delivery.Receipt.PlanDigest != freshDigest {
			t.Fatalf("receipt did not bind reserved plan: %#v", delivery.Receipt)
		}
	}
}

func TestHostsMutationAfterReviewFailsBeforeReservation(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	request := currentCommandRequest(t, now, "req_0123456789abcdefghij", []string{"api", "user"})
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	shownDigest := trustedPlanDigest(t, store, request.ID)
	if err := os.WriteFile(filepath.Join(store.execution.GitHubConfigDir, "hosts.yml"), []byte("github.example.invalid:\n  user: changed-test-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", shownDigest); !errors.Is(err, ErrExecutionFailed) {
		t.Fatalf("mutated hosts.yml execution=%v", err)
	}
	if runner.Calls() != 0 {
		t.Fatal("mutated hosts.yml reached the provider runner")
	}
	record, _, found := store.Record(request.ID)
	if !found || record.State != "pending" || len(record.Attempts) != 0 || len(record.Receipts) != 0 {
		t.Fatalf("mutated hosts.yml reserved execution: %#v", record)
	}
}

func TestExecutableIdentityChangeAfterReviewFailsBeforeChild(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	source := staticFakeGH(t, root)
	executable := filepath.Join(root, "configured-gh")
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(executable, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		_ = input.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	if err := errors.Join(copyErr, input.Close(), output.Close()); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(root, "gh-config")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "hosts.yml"), []byte("github.example.invalid:\n  user: test-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	execution := trustedTestExecutionConfig(configDir)
	execution.GitHubCLIPath = executable
	execution.ExecutableSHA256 = ""
	launcherDigest, err := computeSandboxLauncherSHA256ForTest(execution.SandboxCLIPath)
	if err != nil {
		skipOrFailRealSandbox(t, "real bwrap sandbox is unavailable: %v", err)
	}
	execution.sandboxLauncherDigestForTest = launcherDigest
	store, err := NewStore(root, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, execution)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{started: make(chan struct{}, 1)}
	store.runner = runner
	now := time.Now().UTC().Truncate(time.Second)
	store.now = func() time.Time { return now }
	request := currentCommandRequest(t, now, "req_0123456789abcdefghij", []string{"api", "user"})
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	shownDigest := trustedPlanDigest(t, store, request.ID)
	file, err := os.OpenFile(executable, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("changed")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", shownDigest); err != ErrExecutionFailed {
		t.Fatalf("changed executable result=%v", err)
	}
	if runner.Calls() != 0 {
		t.Fatal("changed executable reached child invocation")
	}
	record, _, _ := store.Record(request.ID)
	if record.State != "pending" || len(record.Attempts) != 0 || len(record.Receipts) != 0 {
		t.Fatalf("changed executable was not rejected before reservation: %#v", record)
	}
}

func TestExecutableRenameSwapAfterReviewNeverReachesRunner(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := staticFakeGH(t, root)
	replacement := filepath.Join(root, "replacement-gh")
	input, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(replacement, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		_ = input.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	if err := errors.Join(copyErr, input.Close(), output.Close()); err != nil {
		t.Fatal(err)
	}
	if file, err := os.OpenFile(replacement, os.O_WRONLY|os.O_APPEND, 0); err != nil {
		t.Fatal(err)
	} else if _, err := file.Write([]byte("replacement-bytes")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	} else if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(root, "gh-config")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "hosts.yml"), []byte("github.example.invalid:\n  user: test-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	execution := trustedTestExecutionConfig(configDir)
	execution.GitHubCLIPath = executable
	execution.ExecutableSHA256 = ""
	store, err := NewStore(root, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, execution)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{started: make(chan struct{}, 1)}
	store.runner = runner
	now := time.Now().UTC().Truncate(time.Second)
	store.now = func() time.Time { return now }
	request := currentCommandRequest(t, now, "req_0123456789abcdefghij", []string{"api", "user"})
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	shownDigest := trustedPlanDigest(t, store, request.ID)
	if err := os.Rename(replacement, executable); err != nil {
		t.Fatal(err)
	}
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", shownDigest); !errors.Is(err, ErrExecutionFailed) {
		t.Fatalf("renamed executable execution=%v", err)
	}
	if runner.Calls() != 0 {
		t.Fatal("replacement executable reached the provider runner")
	}
	record, _, _ := store.Record(request.ID)
	if record.State != "pending" || len(record.Attempts) != 0 || len(record.Receipts) != 0 {
		t.Fatalf("replacement executable reserved execution: %#v", record)
	}
}

func TestDurablePlanTamperingIsRejectedAgainstSignedApproval(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, _ := trustedTestStore(t, privateKey, now)
	request := currentCommandRequest(t, now, "req_0123456789abcdefghij", []string{"api", "repos/example/project"})
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID)); err != nil {
		t.Fatal(err)
	}
	record := cloneRecord(store.state.Requests[request.ID])
	record.Attempts[0].Plan.Argv[0] = "auth"
	if err := setExecutionPlanDigest(record.Attempts[0].Plan); err != nil {
		t.Fatal(err)
	}
	record.Attempts[0].PlanDigest = record.Attempts[0].Plan.Digest
	tampered := clonePersistedState(store.state)
	tampered.Requests[request.ID] = record
	if err := store.commit(tampered); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(filepath.Dir(store.path), privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, *store.execution); err == nil {
		t.Fatal("self-consistent tampered plan was silently removed during recovery")
	}
	after, err := os.ReadFile(store.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("tampered trusted state was rewritten: err=%v", err)
	}
}

func TestDirectGenericCommandUsesExactArgvFreshStateAndNoAmbientOrOutputEgress(t *testing.T) {
	if testing.Short() {
		if os.Getenv("CI") != "" {
			t.Fatal("real Bubblewrap execution coverage must not be skipped in CI")
		}
		t.Skip("process-shaped direct execution test")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := staticFakeGH(t, root)
	configDir := filepath.Join(root, "canonical-gh-config")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "hosts.yml"), []byte("github.example.invalid:\n  user: test-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	execution := trustedTestExecutionConfig(configDir)
	execution.GitHubCLIPath = executable
	execution.ExecutableSHA256 = ""
	launcherDigest, err := computeSandboxLauncherSHA256ForTest(execution.SandboxCLIPath)
	if err != nil {
		skipOrFailRealSandbox(t, "real bwrap sandbox is unavailable: %v", err)
	}
	execution.sandboxLauncherDigestForTest = launcherDigest
	store, err := NewStore(root, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, execution)
	if err != nil {
		t.Fatal(err)
	}
	store.runner = directExecutionRunner{}
	now := time.Now().UTC().Truncate(time.Second)
	store.now = func() time.Time { return now }
	t.Setenv("GH_TOKEN", "ambient-gh-token-must-not-leak")
	t.Setenv("GITHUB_TOKEN", "ambient-github-token-must-not-leak")
	t.Setenv("HTTPS_PROXY", "http://ambient-proxy.invalid")
	t.Setenv("HOME", "/ambient/home/must-not-leak")
	wantArgv := []string{";", "$(id)", "a && b", "--method", "DELETE"}
	var previews []string
	for index := range 2 {
		id := fmt.Sprintf("req_0123456789abcdefghi%c", 'j'+index)
		argv := append([]string{"inspect"}, wantArgv...)
		request := currentCommandRequest(t, now, id, argv)
		if err := store.Ingest(request); err != nil {
			t.Fatal(err)
		}
		if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID)); err != nil {
			record, _, _ := store.Record(request.ID)
			t.Fatalf("direct sandbox execution: %v attempts=%#v", err, record.Attempts)
		}
		record, _, found := store.Record(id)
		if !found || len(record.Attempts) != 1 || record.Attempts[0].OutputPreview == nil {
			t.Fatalf("trusted preview was not retained locally: %#v", record)
		}
		previews = append(previews, record.Attempts[0].OutputPreview.Stdout)
	}
	for _, preview := range previews {
		line, found := strings.CutPrefix(preview, "AIRLOCK_SNAPSHOT:")
		if !found {
			t.Fatalf("trusted preview omitted snapshot: %q", preview)
		}
		line, _, _ = strings.Cut(line, "\n")
		var snapshot struct {
			Argv []string `json:"argv"`
			Env  []string `json:"env"`
			CWD  string   `json:"cwd"`
		}
		if err := json.Unmarshal([]byte(line), &snapshot); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(snapshot.Argv, wantArgv) {
			t.Fatalf("shell data was interpreted or argv changed: %#v", snapshot.Argv)
		}
		seen := map[string]string{}
		for _, entry := range snapshot.Env {
			key, value, ok := strings.Cut(entry, "=")
			if !ok {
				t.Fatalf("malformed environment entry %q", entry)
			}
			seen[key] = value
		}
		for _, key := range []string{"GH_CONFIG_DIR", "GH_PROMPT_DISABLED", "GH_NO_UPDATE_NOTIFIER", "NO_COLOR", "TERM", "HOME", "LC_ALL", "PATH", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"} {
			if _, ok := seen[key]; !ok {
				t.Fatalf("fixed child environment omitted %s: %#v", key, snapshot.Env)
			}
		}
		for _, forbidden := range []string{"ambient-gh-token", "ambient-github-token", "ambient-proxy", "/ambient/home"} {
			if strings.Contains(strings.Join(snapshot.Env, "\n"), forbidden) {
				t.Fatalf("ambient value leaked to child: %s", forbidden)
			}
		}
		if seen["HOME"] != "/airlock/home" || seen["GH_CONFIG_DIR"] != "/airlock/home/.config/gh" || seen["GH_CONFIG_DIR"] == configDir {
			t.Fatalf("child did not receive an ephemeral GitHub home: %#v", snapshot.Env)
		}
		if snapshot.CWD != "/airlock/work" {
			t.Fatalf("working directory was not ephemeral: %q", snapshot.CWD)
		}
	}
	if _, err := os.Stat(filepath.Join(configDir, "poisoned-alias")); !os.IsNotExist(err) {
		t.Fatalf("child poisoned canonical GitHub config: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "invocations"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("ephemeral invocation state was not cleaned: entries=%d err=%v", len(entries), err)
	}
	state, err := json.Marshal(store.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{fakeGHOutputCanary, "\x1b[31m"} {
		if strings.Contains(string(state), forbidden) {
			t.Fatalf("raw child output leaked to durable state: %q", forbidden)
		}
	}
	for _, preview := range previews {
		if !strings.Contains(preview, "[REDACTED]") || !strings.Contains(preview, outputTruncationMarker) {
			t.Fatalf("trusted output was not redacted and truthfully bounded: %q", preview)
		}
	}
}

func TestPreparedInvocationUsesConfiguredCanonicalSandboxLauncher(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, runner := trustedTestStore(t, privateKey, now)
	request := currentCommandRequest(t, now, "req_0123456789abcdefghij", []string{"api", "user"})
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID)); err != nil {
		t.Fatal(err)
	}
	if got, want := runner.plan.runtimeSandboxLauncher, store.execution.SandboxCLIPath; got != want {
		t.Fatalf("runtime launcher=%q want configured canonical launcher %q", got, want)
	}
	if strings.HasPrefix(runner.plan.runtimeSandboxLauncher, store.executionRoot+string(filepath.Separator)) {
		t.Fatalf("runtime launcher used invocation-local copy: %q", runner.plan.runtimeSandboxLauncher)
	}
}

func TestRealBubblewrapSandboxDeniesHostSecretsAndCanonicalState(t *testing.T) {
	if testing.Short() {
		if os.Getenv("CI") != "" {
			t.Fatal("real Bubblewrap sandbox coverage must not be skipped in CI")
		}
		t.Skip("real bwrap sabotage matrix")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(root, "trusted-state")
	configDir := filepath.Join(root, "canonical-gh-config")
	operatorHome := filepath.Join(root, "operator-home")
	for _, directory := range []string{stateDir, configDir, operatorHome} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, contents := range map[string]string{
		filepath.Join(configDir, "hosts.yml"):   "github.example.invalid:\n  user: test-only\n",
		filepath.Join(configDir, "aliases.yml"): "evil: api user\n",
		filepath.Join(operatorHome, "canary"):   "operator-home\n",
		filepath.Join(root, "signing-canary"):   "signing-key\n",
		filepath.Join(root, "unrelated-canary"): "unrelated-credential\n",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(configDir, "extensions"), 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(stateDir, "control.sock")
	listener, listenerErr := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if listenerErr != nil {
		// This outer test sandbox forbids AF_UNIX creation. Keep exercising the
		// real bwrap filesystem boundary with the same protected socket path;
		// control-plane lifecycle tests cover a real socket where AF_UNIX exists.
		t.Logf("AF_UNIX control-socket fixture unavailable: %v", listenerErr)
		if err := os.WriteFile(socketPath, []byte("control-socket-canary"), 0o600); err != nil {
			t.Fatal(err)
		}
	} else {
		defer listener.Close()
	}
	gh := staticFakeGH(t, root)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	execution := trustedTestExecutionConfig(configDir)
	execution.GitHubCLIPath = gh
	execution.ExecutableSHA256 = ""
	launcherDigest, err := computeSandboxLauncherSHA256ForTest(execution.SandboxCLIPath)
	if err != nil {
		skipOrFailRealSandbox(t, "real bwrap sandbox is unavailable: %v", err)
	}
	execution.sandboxLauncherDigestForTest = launcherDigest
	store, err := NewStore(stateDir, privateKey, trustedTestCapabilities(), 15*time.Minute, time.Hour, execution)
	if err != nil {
		t.Fatal(err)
	}
	store.runner = directExecutionRunner{}
	now := time.Now().UTC().Truncate(time.Second)
	store.now = func() time.Time { return now }
	denied := []string{
		filepath.Join(root, "signing-canary"), filepath.Join(stateDir, "trusted-state.json"), socketPath,
		configDir, filepath.Join(operatorHome, "canary"), filepath.Join(root, "unrelated-canary"),
		"/airlock/home/.config/gh/aliases.yml", "/airlock/home/.config/gh/extensions",
	}
	argv := append([]string{"probe"}, denied...)
	argv = append(argv, "/airlock/work", "/airlock/home/.config/gh/hosts.yml")
	request := currentCommandRequest(t, now, "req_0123456789abcdefghij", argv)
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	if err := store.Execute(context.Background(), request.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, request.ID)); err != nil {
		record, _, _ := store.Record(request.ID)
		preview := ExecutionOutputPreview{}
		if len(record.Attempts) != 0 && record.Attempts[len(record.Attempts)-1].OutputPreview != nil {
			preview = *record.Attempts[len(record.Attempts)-1].OutputPreview
		}
		if sandboxUnavailable(err, preview) {
			skipOrFailRealSandbox(t, "real bwrap/kernel namespaces unavailable: %v", err)
		}
		t.Fatalf("sandbox probe execution: %v", err)
	}
	record, _, found := store.Record(request.ID)
	if !found || len(record.Attempts) != 1 || record.Attempts[0].OutputPreview == nil {
		t.Fatalf("sandbox probe preview missing: %#v", record)
	}
	encoded, found := strings.CutPrefix(record.Attempts[0].OutputPreview.Stdout, "AIRLOCK_PROBE:")
	if !found {
		t.Fatalf("sandbox probe did not emit evidence: %q", record.Attempts[0].OutputPreview.Stdout)
	}
	var observed map[string]bool
	if err := json.Unmarshal([]byte(strings.TrimSpace(encoded)), &observed); err != nil {
		t.Fatal(err)
	}
	for _, path := range denied {
		if observed[path] {
			t.Fatalf("sandbox exposed forbidden host path %q", path)
		}
	}
	for _, path := range []string{"/airlock/work", "/airlock/home/.config/gh/hosts.yml"} {
		if !observed[path] {
			t.Fatalf("sandbox omitted required invocation path %q", path)
		}
	}

	inspect := currentCommandRequest(t, now, "req_0123456789abcdefghik", []string{"inspect"})
	if err := store.Ingest(inspect); err != nil {
		t.Fatal(err)
	}
	if err := store.Execute(context.Background(), inspect.ID, "reviewer@example.invalid", trustedPlanDigest(t, store, inspect.ID)); err != nil {
		t.Fatal(err)
	}
	inspectRecord, _, _ := store.Record(inspect.ID)
	if inspectRecord.Attempts[0].OutputPreview == nil || !strings.Contains(inspectRecord.Attempts[0].OutputPreview.Stdout, `"write_denied":true`) {
		t.Fatalf("sandbox allowed canonical config persistence: %#v", inspectRecord.Attempts)
	}
	if _, err := os.Lstat(filepath.Join(configDir, "poisoned-alias")); !os.IsNotExist(err) {
		t.Fatalf("sandbox persisted canonical config: %v", err)
	}
}

func staticFakeGH(t *testing.T, root string) string {
	t.Helper()
	output := filepath.Join(root, "fake-gh")
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("build static fake gh: %v", err)
	}
	command := exec.Command(goBinary, "build", "-buildvcs=false", "-trimpath", "-o", output, "./testdata/fakegh")
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build static fake gh: %v: %s", err, output)
	}
	return output
}

func TestRiskClassificationAndTrustedReviewShowExactCanonicalCommand(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, _ := trustedTestStore(t, privateKey, now)
	request := currentCommandRequest(t, now, "req_0123456789abcdefghij", []string{"api", "--method", "DELETE", "repos/example/project", ";", "$(id)"})
	if err := store.Ingest(request); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(store, []string{"reviewer@example.invalid"}, true)
	if err != nil {
		t.Fatal(err)
	}
	review := trustedRequest(t, "GET", "/requests/"+request.ID, nil, nil)
	review.Header.Set("X-Airlock-Dev-Identity", "reviewer@example.invalid")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, review)
	body := response.Body.String()
	for _, required := range []string{"github.command/v1", "Broad credential authority", "Write-capable GitHub API method", "Executable SHA-256 identity", "Credential snapshot identity", "Sandbox launcher path", "Sandbox launcher SHA-256 identity", "Environment policy", "argv[0] = api", "argv[4] = ;", "argv[5] = $(id)", request.Digest} {
		if !strings.Contains(body, required) {
			t.Fatalf("trusted review omitted %q: %s", required, body)
		}
	}
	if strings.Count(body, "argv[") != len(request.Argv) {
		t.Fatalf("trusted review did not distinguish every argv element: %s", body)
	}
}

func currentCommandRequest(t *testing.T, now time.Time, id string, argv []string) model.Request {
	t.Helper()
	request := model.Request{
		Version: model.RequestVersion, ID: id, ProfileID: model.ProfileGitHubCommandID, ProfileVersion: model.ProfileGitHubCommandVersion,
		Argv: append([]string(nil), argv...), Reason: "Review this exact GitHub command",
		CreatedAt: model.Timestamp(now), ExpiresAt: model.Timestamp(now.Add(10 * time.Minute)), Nonce: "0123456789abcdefghijklmnopqrstuv",
	}
	if err := model.SetRequestDigest(&request); err != nil {
		t.Fatal(err)
	}
	return request
}
