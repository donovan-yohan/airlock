//go:build !linux

package trusted

import (
	"context"
	"errors"
)

// Trusted serving is Linux-only; retain a fail-closed implementation for
// compile-time portability instead of silently running an unsandboxed child.
func runDirectCommand(context.Context, ExecutionPlan, []string) (ExecutionOutputPreview, error) {
	return ExecutionOutputPreview{}, errors.New("trusted command sandbox requires Linux")
}
