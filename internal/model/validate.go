package model

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MaxCapabilities = 64
	MaxReasonBytes  = 512
	ClockSkew       = 2 * time.Minute
)

var (
	capabilityIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9:._-]{0,127}$`)
	objectIDPattern      = regexp.MustCompile(`^(req|rec)_[A-Za-z0-9_-]{20,80}$`)
	noncePattern         = regexp.MustCompile(`^[A-Za-z0-9_-]{24,96}$`)
	digestPattern        = regexp.MustCompile(`^[a-f0-9]{64}$`)
	githubUserPattern    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	githubRepoPattern    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$`)
	likelySecretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`),
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
		regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`),
		regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`),
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}\b`),
		regexp.MustCompile(`(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\s*[:=]\s*\S{8,}`),
		regexp.MustCompile(`\b[A-Za-z0-9_-]{80,}\b`),
	}
)

func ValidateCatalog(c Catalog, now time.Time, maxLifetime time.Duration) error {
	if c.Version != CatalogVersion {
		return errors.New("unsupported catalog version")
	}
	issued, expires, err := validateWindow(c.IssuedAt, c.ExpiresAt, now, maxLifetime)
	if err != nil {
		return fmt.Errorf("catalog time window: %w", err)
	}
	if issued.After(now.Add(ClockSkew)) {
		return errors.New("catalog issued in the future")
	}
	if !expires.After(now) {
		return errors.New("catalog expired")
	}
	if len(c.Capabilities) == 0 || len(c.Capabilities) > MaxCapabilities {
		return errors.New("catalog capability count out of bounds")
	}
	ids := make([]string, 0, len(c.Capabilities))
	seen := make(map[string]struct{}, len(c.Capabilities))
	for _, capability := range c.Capabilities {
		if err := ValidateCapability(capability); err != nil {
			return fmt.Errorf("capability %q: %w", capability.ID, err)
		}
		if _, exists := seen[capability.ID]; exists {
			return fmt.Errorf("duplicate capability %q", capability.ID)
		}
		seen[capability.ID] = struct{}{}
		ids = append(ids, capability.ID)
	}
	if !sort.StringsAreSorted(ids) {
		return errors.New("catalog capabilities must be sorted by id")
	}
	return nil
}

func ValidateCapability(c Capability) error {
	if !capabilityIDPattern.MatchString(c.ID) {
		return errors.New("invalid capability id")
	}
	if err := validateText(c.DisplayName, 1, 100); err != nil {
		return fmt.Errorf("display name: %w", err)
	}
	if len(c.Actions) != 1 || c.Actions[0] != ActionGitHubAddCollaborator {
		return errors.New("unsupported action set")
	}
	if !githubUserPattern.MatchString(c.Constraints.Owner) {
		return errors.New("invalid GitHub owner")
	}
	if !githubUserPattern.MatchString(c.Constraints.Collaborator) {
		return errors.New("invalid GitHub collaborator")
	}
	if len(c.Constraints.Permissions) == 0 || len(c.Constraints.Permissions) > 2 {
		return errors.New("permission count out of bounds")
	}
	if !sort.StringsAreSorted(c.Constraints.Permissions) {
		return errors.New("permissions must be sorted")
	}
	seen := map[string]bool{}
	for _, permission := range c.Constraints.Permissions {
		if permission != "pull" && permission != "push" {
			return errors.New("unsupported permission")
		}
		if seen[permission] {
			return errors.New("duplicate permission")
		}
		seen[permission] = true
	}
	return nil
}

func ValidateRequest(r Request, now time.Time, maxLifetime time.Duration) error {
	if r.Version != RequestVersion {
		return errors.New("unsupported request version")
	}
	if !objectIDPattern.MatchString(r.ID) || !strings.HasPrefix(r.ID, "req_") {
		return errors.New("invalid request id")
	}
	if !capabilityIDPattern.MatchString(r.CapabilityID) {
		return errors.New("invalid capability id")
	}
	if r.Action != ActionGitHubAddCollaborator {
		return errors.New("unsupported request action")
	}
	if !noncePattern.MatchString(r.Nonce) {
		return errors.New("invalid request nonce")
	}
	if !digestPattern.MatchString(r.Digest) {
		return errors.New("invalid request digest")
	}
	if err := ValidateReason(r.Reason); err != nil {
		return err
	}
	created, expires, err := validateWindow(r.CreatedAt, r.ExpiresAt, now, maxLifetime)
	if err != nil {
		return fmt.Errorf("request time window: %w", err)
	}
	if created.After(now.Add(ClockSkew)) {
		return errors.New("request created in the future")
	}
	if !expires.After(now) {
		return errors.New("request expired")
	}
	if err := ValidateGitHubArguments(r.Arguments); err != nil {
		return err
	}
	return VerifyRequestDigest(r)
}

// ValidateReason rejects control text and high-confidence credential shapes.
// It is a narrow persistence guard, not a general-purpose secret scanner.
func ValidateReason(reason string) error {
	if err := validateText(reason, 1, MaxReasonBytes); err != nil {
		return fmt.Errorf("reason: %w", err)
	}
	for _, pattern := range likelySecretPatterns {
		if pattern.MatchString(reason) {
			return errors.New("reason appears to contain credential material; describe it without the value")
		}
	}
	return nil
}

func ValidateGitHubArguments(arguments map[string]string) error {
	if len(arguments) != 2 {
		return errors.New("arguments must contain exactly repository and permission")
	}
	repository, hasRepository := arguments["repository"]
	permission, hasPermission := arguments["permission"]
	if !hasRepository || !hasPermission {
		return errors.New("arguments must contain repository and permission")
	}
	if !githubRepoPattern.MatchString(repository) || repository == "." || repository == ".." || strings.Contains(repository, "..") {
		return errors.New("invalid GitHub repository name")
	}
	if permission != "pull" && permission != "push" {
		return errors.New("invalid GitHub permission")
	}
	return nil
}

func ValidateRequestAgainstCapability(r Request, capability Capability) error {
	if r.CapabilityID != capability.ID {
		return errors.New("request capability does not match")
	}
	if len(capability.Actions) != 1 || r.Action != capability.Actions[0] {
		return errors.New("request action is not advertised")
	}
	permission := r.Arguments["permission"]
	for _, allowed := range capability.Constraints.Permissions {
		if permission == allowed {
			return nil
		}
	}
	return errors.New("permission is not allowed by capability")
}

func ValidateReceipt(r Receipt, now time.Time, maxLifetime time.Duration) error {
	if r.Version != ReceiptVersion {
		return errors.New("unsupported receipt version")
	}
	if !objectIDPattern.MatchString(r.ID) || !strings.HasPrefix(r.ID, "rec_") {
		return errors.New("invalid receipt id")
	}
	if !objectIDPattern.MatchString(r.RequestID) || !strings.HasPrefix(r.RequestID, "req_") {
		return errors.New("invalid receipt request id")
	}
	if !digestPattern.MatchString(r.RequestDigest) {
		return errors.New("invalid receipt request digest")
	}
	if r.Decision != DecisionApprove && r.Decision != DecisionDeny && r.Decision != DecisionExecute {
		return errors.New("invalid receipt decision")
	}
	if err := validateText(r.Reviewer, 1, 254); err != nil {
		return fmt.Errorf("reviewer: %w", err)
	}
	if r.AdapterVersion != AdapterGitHubAddCollaboratorV1 {
		return errors.New("unsupported adapter version")
	}
	if r.Evidence != "" {
		return errors.New("receipt evidence is not supported by the MVP")
	}
	created, expires, err := validateWindow(r.CreatedAt, r.ExpiresAt, now, maxLifetime)
	if err != nil {
		return fmt.Errorf("receipt time window: %w", err)
	}
	if created.After(now.Add(ClockSkew)) {
		return errors.New("receipt created in the future")
	}
	if !expires.After(now) {
		return errors.New("receipt expired")
	}
	return nil
}

func NextRequestState(current, decision string) (string, error) {
	switch {
	case current == "pending" && decision == DecisionApprove:
		return "approved", nil
	case current == "pending" && decision == DecisionDeny:
		return "denied", nil
	case current == "approved" && decision == DecisionExecute:
		return "manually_executed", nil
	default:
		return "", fmt.Errorf("invalid transition from %q using %q", current, decision)
	}
}

func FindCapability(capabilities []Capability, id string) (Capability, bool) {
	for _, capability := range capabilities {
		if capability.ID == id {
			return capability, true
		}
	}
	return Capability{}, false
}

func validateWindow(createdRaw, expiresRaw string, now time.Time, maxLifetime time.Duration) (time.Time, time.Time, error) {
	created, err := time.Parse(time.RFC3339, createdRaw)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("invalid created timestamp")
	}
	expires, err := time.Parse(time.RFC3339, expiresRaw)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("invalid expiry timestamp")
	}
	if !expires.After(created) {
		return time.Time{}, time.Time{}, errors.New("expiry must follow creation")
	}
	if maxLifetime <= 0 || expires.Sub(created) > maxLifetime {
		return time.Time{}, time.Time{}, errors.New("lifetime exceeds configured maximum")
	}
	return created, expires, nil
}

func validateText(value string, minBytes, maxBytes int) error {
	if len(value) < minBytes || len(value) > maxBytes || !utf8.ValidString(value) {
		return errors.New("length or UTF-8 is invalid")
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return errors.New("control characters are not allowed")
		}
	}
	return nil
}
