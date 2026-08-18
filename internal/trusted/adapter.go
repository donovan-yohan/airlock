package trusted

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/donovan-yohan/airlock/internal/config"
	"github.com/donovan-yohan/airlock/internal/model"
)

// ExecutionPlan is the immutable, secret-free trusted resolution persisted
// with an approval. The runner consumes these exact fields; display text is
// always derived and is never executable input.
type ExecutionPlan struct {
	RequestDigest           string   `json:"request_digest"`
	ProfileID               string   `json:"profile_id"`
	ProfileVersion          string   `json:"profile_version"`
	Executable              string   `json:"executable"`
	ExecutableSHA256        string   `json:"executable_sha256"`
	CredentialSourceID      string   `json:"credential_source_id"`
	SandboxLauncher         string   `json:"sandbox_launcher"`
	SandboxLauncherSHA256   string   `json:"sandbox_launcher_sha256"`
	Argv                    []string `json:"argv"`
	CredentialAuthority     string   `json:"credential_authority"`
	ExecutionIdentity       string   `json:"execution_identity"`
	SandboxPolicy           string   `json:"sandbox_policy"`
	NetworkPolicy           string   `json:"network_policy"`
	WorkingDirectoryPolicy  string   `json:"working_directory_policy"`
	OutputPolicy            string   `json:"output_policy"`
	EnvironmentPolicy       []string `json:"environment_policy"`
	TimeoutMilliseconds     int64    `json:"timeout_milliseconds"`
	ProfileConfigVersion    string   `json:"profile_config_version"`
	LegacyAdapter           string   `json:"legacy_adapter,omitempty"`
	Digest                  string   `json:"digest"`
	runtimeWorkingDirectory string   `json:"-"`
	runtimeExecutable       string   `json:"-"`
	runtimeSandboxLauncher  string   `json:"-"`
}

type executionPlanPayload struct {
	RequestDigest          string   `json:"request_digest"`
	ProfileID              string   `json:"profile_id"`
	ProfileVersion         string   `json:"profile_version"`
	Executable             string   `json:"executable"`
	ExecutableSHA256       string   `json:"executable_sha256"`
	CredentialSourceID     string   `json:"credential_source_id"`
	SandboxLauncher        string   `json:"sandbox_launcher"`
	SandboxLauncherSHA256  string   `json:"sandbox_launcher_sha256"`
	Argv                   []string `json:"argv"`
	CredentialAuthority    string   `json:"credential_authority"`
	ExecutionIdentity      string   `json:"execution_identity"`
	SandboxPolicy          string   `json:"sandbox_policy"`
	NetworkPolicy          string   `json:"network_policy"`
	WorkingDirectoryPolicy string   `json:"working_directory_policy"`
	OutputPolicy           string   `json:"output_policy"`
	EnvironmentPolicy      []string `json:"environment_policy"`
	TimeoutMilliseconds    int64    `json:"timeout_milliseconds"`
	ProfileConfigVersion   string   `json:"profile_config_version"`
	LegacyAdapter          string   `json:"legacy_adapter,omitempty"`
}

func executionPlanSigningBytes(plan ExecutionPlan) ([]byte, error) {
	return json.Marshal(executionPlanPayload{
		RequestDigest: plan.RequestDigest, ProfileID: plan.ProfileID, ProfileVersion: plan.ProfileVersion,
		Executable: plan.Executable, ExecutableSHA256: plan.ExecutableSHA256, CredentialSourceID: plan.CredentialSourceID,
		SandboxLauncher: plan.SandboxLauncher, SandboxLauncherSHA256: plan.SandboxLauncherSHA256,
		Argv: plan.Argv, CredentialAuthority: plan.CredentialAuthority,
		ExecutionIdentity: plan.ExecutionIdentity, SandboxPolicy: plan.SandboxPolicy,
		NetworkPolicy: plan.NetworkPolicy, WorkingDirectoryPolicy: plan.WorkingDirectoryPolicy,
		OutputPolicy: plan.OutputPolicy, EnvironmentPolicy: plan.EnvironmentPolicy,
		TimeoutMilliseconds: plan.TimeoutMilliseconds, ProfileConfigVersion: plan.ProfileConfigVersion,
		LegacyAdapter: plan.LegacyAdapter,
	})
}

func setExecutionPlanDigest(plan *ExecutionPlan) error {
	encoded, err := executionPlanSigningBytes(*plan)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(encoded)
	plan.Digest = hex.EncodeToString(sum[:])
	return nil
}

func verifyExecutionPlanDigest(plan ExecutionPlan) error {
	if len(plan.Digest) != sha256.Size*2 || strings.ToLower(plan.Digest) != plan.Digest {
		return errors.New("invalid resolved plan digest")
	}
	provided, err := hex.DecodeString(plan.Digest)
	if err != nil || len(provided) != sha256.Size {
		return errors.New("invalid resolved plan digest")
	}
	encoded, err := executionPlanSigningBytes(plan)
	if err != nil {
		return err
	}
	expected := sha256.Sum256(encoded)
	if hex.EncodeToString(expected[:]) != plan.Digest {
		return errors.New("resolved plan digest mismatch")
	}
	return nil
}

func resolveExecutionPlan(request model.Request, capabilities []config.TrustedCapability, now time.Time, requestMaxTTL time.Duration, execution *ExecutionConfig) (ExecutionPlan, error) {
	if execution == nil {
		return ExecutionPlan{}, ErrExecutionUnavailable
	}
	credentialSourceID := execution.CredentialSourceID
	if credentialSourceID == "" {
		var err error
		credentialSourceID, err = credentialSourceIdentity(execution.GitHubConfigDir)
		if err != nil {
			return ExecutionPlan{}, fmt.Errorf("resolve minimal GitHub authentication snapshot: %w", err)
		}
	}
	if !validTrustedDigest(credentialSourceID) {
		return ExecutionPlan{}, errors.New("trusted execution credential source is unavailable")
	}
	if err := model.ValidateRequest(request, now, requestMaxTTL); err != nil {
		return ExecutionPlan{}, err
	}
	if !filepath.IsAbs(execution.GitHubCLIPath) || filepath.Clean(execution.GitHubCLIPath) != execution.GitHubCLIPath {
		return ExecutionPlan{}, errors.New("trusted executable is not a clean absolute path")
	}
	argv := append([]string(nil), request.Argv...)
	legacyAdapter := ""
	if request.Version == model.RequestVersion {
		if err := model.ValidateRequestAgainstProfile(request, execution.Profile); err != nil {
			return ExecutionPlan{}, err
		}
	} else {
		local, found := findLegacyCapability(capabilities, request.CapabilityID)
		if !found || local.Adapter != model.AdapterGitHubAddCollaboratorV1 {
			return ExecutionPlan{}, errors.New("unknown local legacy capability")
		}
		capability := local.CatalogCapability()
		if err := model.ValidateRequestAgainstCapability(request, capability); err != nil {
			return ExecutionPlan{}, err
		}
		argv = []string{
			"api", "--method", "PUT",
			fmt.Sprintf("repos/%s/%s/collaborators/%s", local.Owner, request.Arguments["repository"], local.Collaborator),
			"-f", "permission=" + request.Arguments["permission"], "--silent",
		}
		legacyAdapter = local.Adapter
	}
	plan := ExecutionPlan{
		RequestDigest: request.Digest, ProfileID: execution.Profile.ID, ProfileVersion: execution.Profile.Version,
		Executable: execution.GitHubCLIPath, ExecutableSHA256: execution.ExecutableSHA256,
		CredentialSourceID: credentialSourceID, SandboxLauncher: execution.SandboxCLIPath,
		SandboxLauncherSHA256: execution.SandboxCLISHA256, Argv: argv,
		CredentialAuthority: execution.Profile.AuthorityLabel, ExecutionIdentity: execution.ExecutionIdentity,
		SandboxPolicy: execution.Profile.SandboxLabel, NetworkPolicy: execution.Profile.NetworkLabel,
		WorkingDirectoryPolicy: execution.Profile.CWDLabel, OutputPolicy: execution.Profile.OutputLabel,
		EnvironmentPolicy:   reviewedChildEnvironment(),
		TimeoutMilliseconds: execution.Timeout.Milliseconds(), ProfileConfigVersion: execution.ProfileConfigVersion,
		LegacyAdapter: legacyAdapter,
	}
	if err := setExecutionPlanDigest(&plan); err != nil {
		return ExecutionPlan{}, err
	}
	return plan, nil
}

func reviewedChildEnvironment() []string {
	return append(minimalChildEnvironment(), "PWD=/airlock/work")
}

// validateAndPlan is retained for historical v1 recovery tests. Serving paths
// resolve through the complete trusted ExecutionConfig above.
func validateAndPlan(request model.Request, capabilities []config.TrustedCapability, now time.Time, requestMaxTTL time.Duration, executable string) (ExecutionPlan, error) {
	profile := model.CommandProfile{ID: model.ProfileGitHubCommandID, Version: model.ProfileGitHubCommandVersion, DisplayName: "GitHub CLI command", AuthorityLabel: "Broad GitHub authority", SandboxLabel: "Ephemeral local state", NetworkLabel: "GitHub network", CWDLabel: "Ephemeral directory", OutputLabel: "Bounded sanitized trusted-local output preview", Limits: model.ProfileLimits{MaxArgvCount: model.MaxArgvCount, MaxArgumentBytes: model.MaxArgumentBytes, MaxAggregateBytes: model.MaxArgvAggregateBytes}}
	return resolveExecutionPlan(request, capabilities, now, requestMaxTTL, &ExecutionConfig{GitHubCLIPath: executable, GitHubConfigDir: "/nonexistent-test-config", CredentialSourceID: strings.Repeat("0", sha256.Size*2), SandboxCLIPath: "/usr/bin/bwrap", SandboxCLISHA256: strings.Repeat("0", sha256.Size*2), ExecutableSHA256: strings.Repeat("0", sha256.Size*2), Timeout: time.Minute, Profile: profile, ProfileConfigVersion: "compat-v1", ExecutionIdentity: "trusted test identity"})
}

func findLegacyCapability(capabilities []config.TrustedCapability, id string) (config.TrustedCapability, bool) {
	for _, capability := range capabilities {
		if capability.ID == id {
			return capability, true
		}
	}
	return config.TrustedCapability{}, false
}

func escapedCommand(plan ExecutionPlan) string {
	parts := make([]string, 0, len(plan.Argv)+1)
	parts = append(parts, strconv.Quote(plan.Executable))
	for _, argument := range plan.Argv {
		parts = append(parts, strconv.Quote(argument))
	}
	display := strings.Join(parts, " ")
	if len(display) > model.MaxDisplayBytes {
		return "[non-executable convenience rendering omitted: exceeds display limit; review the distinct argv elements]"
	}
	return display
}

func classifyGitHubRisk(argv []string) []string {
	warnings := []string{"Broad credential authority: approval permits this exact gh command to act with the configured credential. This is reviewer-approved RCE within that profile."}
	lower := make([]string, len(argv))
	for index, argument := range argv {
		lower[index] = strings.ToLower(argument)
	}
	joined := " " + strings.Join(lower, " ") + " "
	shapes := []struct {
		label   string
		needles []string
	}{
		{"Authentication or local GitHub configuration change", []string{" auth ", " config ", " alias ", " extension "}},
		{"Write-capable GitHub API method", []string{" --method post ", " --method=post ", " --method put ", " --method=put ", " --method patch ", " --method=patch ", " --method delete ", " --method=delete ", " -x post ", " -xpost ", " -x put ", " -xput ", " -x patch ", " -xpatch ", " -x delete ", " -xdelete "}},
		{"Merge operation", []string{" pr merge "}},
		{"Release mutation", []string{" release create ", " release delete ", " release edit ", " release upload "}},
		{"Workflow dispatch", []string{" workflow run "}},
		{"Repository visibility, transfer, archive, rename, or deletion shape", []string{" --visibility ", " --visibility=", " transfer ", " repo archive ", " repo rename ", " repo delete ", " delete repository ", " delete repo "}},
	}
	for _, shape := range shapes {
		for _, needle := range shape.needles {
			if strings.Contains(joined, needle) {
				warnings = append(warnings, shape.label)
				break
			}
		}
	}
	return warnings
}
