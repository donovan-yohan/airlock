package trusted

import (
	"errors"
	"fmt"
	"time"

	"github.com/donovan-yohan/airlock/internal/config"
	"github.com/donovan-yohan/airlock/internal/model"
)

func validateAndRender(request model.Request, capabilities []config.TrustedCapability, now time.Time, requestMaxTTL time.Duration) (string, string, error) {
	if err := model.ValidateRequest(request, now, requestMaxTTL); err != nil {
		return "", "", err
	}
	for _, local := range capabilities {
		if local.ID != request.CapabilityID {
			continue
		}
		if local.Adapter != model.AdapterGitHubAddCollaboratorV1 {
			return "", "", errors.New("unsupported local adapter")
		}
		capability := local.CatalogCapability()
		if err := model.ValidateCapability(capability); err != nil {
			return "", "", fmt.Errorf("invalid local capability: %w", err)
		}
		if err := model.ValidateRequestAgainstCapability(request, capability); err != nil {
			return "", "", err
		}
		command := fmt.Sprintf(
			"gh api --method PUT repos/%s/%s/collaborators/%s -f permission=%s --silent",
			local.Owner, request.Arguments["repository"], local.Collaborator, request.Arguments["permission"],
		)
		return command, local.Adapter, nil
	}
	return "", "", errors.New("unknown local capability")
}
