package trusted

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/donovan-yohan/airlock/internal/config"
	"github.com/donovan-yohan/airlock/internal/model"
)

// ExecutionPlan is a locally reconstructed direct-exec contract. It has no
// shell text: Executable and Argv are passed unchanged to os/exec.
type ExecutionPlan struct {
	Executable string
	Argv       []string
	Display    string
	Adapter    string
}

func validateAndPlan(request model.Request, capabilities []config.TrustedCapability, now time.Time, requestMaxTTL time.Duration, executable string) (ExecutionPlan, error) {
	if err := model.ValidateRequest(request, now, requestMaxTTL); err != nil {
		return ExecutionPlan{}, err
	}
	if executable != "" && (!filepath.IsAbs(executable) || filepath.Clean(executable) != executable) {
		return ExecutionPlan{}, errors.New("trusted executable is not a clean absolute path")
	}
	for _, local := range capabilities {
		if local.ID != request.CapabilityID {
			continue
		}
		if local.Adapter != model.AdapterGitHubAddCollaboratorV1 {
			return ExecutionPlan{}, errors.New("unsupported local adapter")
		}
		capability := local.CatalogCapability()
		if err := model.ValidateCapability(capability); err != nil {
			return ExecutionPlan{}, fmt.Errorf("invalid local capability: %w", err)
		}
		if err := model.ValidateRequestAgainstCapability(request, capability); err != nil {
			return ExecutionPlan{}, err
		}
		argv := []string{
			"api", "--method", "PUT",
			fmt.Sprintf("repos/%s/%s/collaborators/%s", local.Owner, request.Arguments["repository"], local.Collaborator),
			"-f", "permission=" + request.Arguments["permission"], "--silent",
		}
		displayExecutable := executable
		if displayExecutable == "" {
			displayExecutable = "gh"
		}
		return ExecutionPlan{
			Executable: executable,
			Argv:       argv,
			Display:    displayExecutable + " " + strings.Join(argv, " "),
			Adapter:    local.Adapter,
		}, nil
	}
	return ExecutionPlan{}, errors.New("unknown local capability")
}
