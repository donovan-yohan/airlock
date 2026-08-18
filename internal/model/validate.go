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
	MaxCapabilities       = 64
	MaxProfiles           = 16
	MaxReasonBytes        = 512
	MaxArgvCount          = 64
	MaxArgumentBytes      = 4096
	MaxArgvAggregateBytes = 32768
	MaxDisplayBytes       = 65536
	MaxRequesterRequests  = 192
	ClockSkew             = 2 * time.Minute

	// Persisted envelope lifetimes are protocol limits, deliberately separate
	// from an operator's current admission settings. They let either node read
	// signed history after a routine TTL tightening without reviving it for new
	// work. Keep these equal to the largest supported configured lifetimes.
	PersistedRequestMaxLifetime = time.Hour
	PersistedCatalogMaxLifetime = 24 * time.Hour
	PersistedReceiptMaxLifetime = 7 * 24 * time.Hour
)

var (
	capabilityIDPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9:._-]{0,127}$`)
	profileIDPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	profileVersionPattern    = regexp.MustCompile(`^v[1-9][0-9]{0,3}$`)
	objectIDPattern          = regexp.MustCompile(`^(req|rec)_[A-Za-z0-9_-]{20,80}$`)
	noncePattern             = regexp.MustCompile(`^[A-Za-z0-9_-]{24,96}$`)
	digestPattern            = regexp.MustCompile(`^[a-f0-9]{64}$`)
	githubUserPattern        = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	githubRepoPattern        = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$`)
	likelyCredentialPatterns = []*regexp.Regexp{
		// Keep the complete PEM form first so trusted output redaction removes
		// the body too. The header fallback still rejects a partial value.
		regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[A-Z0-9+/=\r\n-]*-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`),
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
		regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`),
		regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`),
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}\b`),
		regexp.MustCompile(`(?i)\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer|token|basic)\s+[A-Za-z0-9._~+/=-]{8,}\b`),
		regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^/\s@]+@`),
		regexp.MustCompile(`(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\s*[:=]\s*\S{8,}`),
		regexp.MustCompile(`\b[A-Za-z0-9_-]{80,}\b`),
	}
)

func ValidateCatalog(c Catalog, now time.Time, maxLifetime time.Duration) error {
	if c.Version != CatalogVersion && c.Version != CatalogVersionV1 {
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
	if c.Version == CatalogVersionV1 && len(c.Profiles) != 0 {
		return errors.New("legacy catalog contains command profiles")
	}
	if c.Version == CatalogVersion && (len(c.Profiles) == 0 || len(c.Profiles) > MaxProfiles) {
		return errors.New("catalog profile count out of bounds")
	}
	if (c.Version == CatalogVersionV1 && len(c.Capabilities) == 0) || len(c.Capabilities) > MaxCapabilities {
		return errors.New("catalog capability count out of bounds")
	}
	profileKeys := make([]string, 0, len(c.Profiles))
	seenProfiles := make(map[string]struct{}, len(c.Profiles))
	for _, profile := range c.Profiles {
		if err := ValidateCommandProfile(profile); err != nil {
			return fmt.Errorf("profile %q: %w", profile.ID, err)
		}
		key := profile.ID + "/" + profile.Version
		if _, exists := seenProfiles[key]; exists {
			return fmt.Errorf("duplicate profile %q", key)
		}
		seenProfiles[key] = struct{}{}
		profileKeys = append(profileKeys, key)
	}
	if !sort.StringsAreSorted(profileKeys) {
		return errors.New("catalog profiles must be sorted by id and version")
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

// ValidatePersistedCatalog checks the durable protocol envelope without
// requiring that a historical catalog is currently fresh. Signature and
// monotonicity checks remain the caller's responsibility because they depend
// on the trusted key and the surrounding durable state.
func ValidatePersistedCatalog(c Catalog) error {
	return validateAtExpiry(func(now time.Time) error {
		return ValidateCatalog(c, now, PersistedCatalogMaxLifetime)
	}, c.ExpiresAt)
}

func ValidateCommandProfile(p CommandProfile) error {
	if !profileIDPattern.MatchString(p.ID) || !profileVersionPattern.MatchString(p.Version) {
		return errors.New("invalid profile identity")
	}
	if p.ID != ProfileGitHubCommandID || p.Version != ProfileGitHubCommandVersion {
		return errors.New("unsupported enabled command profile")
	}
	for name, value := range map[string]string{
		"display name": p.DisplayName, "authority label": p.AuthorityLabel,
		"sandbox label": p.SandboxLabel, "network label": p.NetworkLabel,
		"cwd label": p.CWDLabel, "output label": p.OutputLabel,
	} {
		if err := validateText(value, 1, 200); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if p.Limits.MaxArgvCount != MaxArgvCount || p.Limits.MaxArgumentBytes != MaxArgumentBytes || p.Limits.MaxAggregateBytes != MaxArgvAggregateBytes {
		return errors.New("unsupported profile limits")
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
	if r.Version != RequestVersion && r.Version != RequestVersionV1 {
		return errors.New("unsupported request version")
	}
	if !objectIDPattern.MatchString(r.ID) || !strings.HasPrefix(r.ID, "req_") {
		return errors.New("invalid request id")
	}
	if !noncePattern.MatchString(r.Nonce) {
		return errors.New("invalid request nonce")
	}
	if !digestPattern.MatchString(r.Digest) {
		return errors.New("invalid request digest")
	}
	if r.Version == RequestVersion {
		if err := ValidateCommandReason(r.Reason); err != nil {
			return err
		}
	} else if err := ValidateReason(r.Reason); err != nil {
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
	if r.Version == RequestVersion {
		if r.CapabilityID != "" || r.Action != "" || r.Arguments != nil {
			return errors.New("command request contains legacy action fields")
		}
		if r.ProfileID != ProfileGitHubCommandID || r.ProfileVersion != ProfileGitHubCommandVersion {
			return errors.New("unsupported command profile")
		}
		if err := ValidateArgv(r.Argv); err != nil {
			return err
		}
	} else {
		if r.ProfileID != "" || r.ProfileVersion != "" || r.Argv != nil {
			return errors.New("legacy request contains command fields")
		}
		if !capabilityIDPattern.MatchString(r.CapabilityID) {
			return errors.New("invalid capability id")
		}
		if r.Action != ActionGitHubAddCollaborator {
			return errors.New("unsupported request action")
		}
		if err := ValidateGitHubArguments(r.Arguments); err != nil {
			return err
		}
	}
	return VerifyRequestDigest(r)
}

// ValidatePersistedRequest validates a historical request against the stable
// protocol envelope. Current policy/capability resolution is intentionally not
// consulted here: it governs new admission and actionability, not evidence.
func ValidatePersistedRequest(r Request) error {
	return validateAtExpiry(func(now time.Time) error {
		return ValidateRequest(r, now, PersistedRequestMaxLifetime)
	}, r.ExpiresAt)
}

func ValidateArgv(argv []string) error {
	if len(argv) == 0 || len(argv) > MaxArgvCount {
		return errors.New("argv count out of bounds")
	}
	aggregate := 0
	for index, argument := range argv {
		if err := validateCurrentCommandText(argument, 1, MaxArgumentBytes); err != nil {
			return fmt.Errorf("argv[%d]: %w", index, err)
		}
		if ContainsLikelyCredential(argument) {
			return fmt.Errorf("argv[%d] appears to contain credential material; omit the value", index)
		}
		aggregate += len(argument)
		if aggregate > MaxArgvAggregateBytes {
			return errors.New("argv aggregate bytes out of bounds")
		}
	}
	return nil
}

// ValidateReason rejects control text and high-confidence credential shapes.
// It is a narrow persistence guard, not a general-purpose secret scanner.
func ValidateReason(reason string) error {
	if err := validateText(reason, 1, MaxReasonBytes); err != nil {
		return fmt.Errorf("reason: %w", err)
	}
	if ContainsLikelyCredential(reason) {
		return errors.New("reason appears to contain credential material; describe it without the value")
	}
	return nil
}

// ContainsLikelyCredential recognizes bounded, high-confidence credential
// values. It is deliberately not a general secret scanner: callers must keep
// accepting ordinary command arguments such as shell metacharacters as data.
func ContainsLikelyCredential(value string) bool {
	for _, pattern := range likelyCredentialPatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

// RedactLikelyCredentials removes only high-confidence credential-shaped
// substrings. It is suitable for bounded trusted-only previews, never as a
// justification to expose raw provider output to requesters.
func RedactLikelyCredentials(value string) string {
	for _, pattern := range likelyCredentialPatterns {
		value = pattern.ReplaceAllString(value, "[REDACTED]")
	}
	return value
}

// ValidateCommandReason keeps historical request recovery unchanged while
// requiring a substantive current proposal reason.
func ValidateCommandReason(reason string) error {
	if err := validateCurrentCommandText(reason, 1, MaxReasonBytes); err != nil {
		return fmt.Errorf("reason: %w", err)
	}
	if ContainsLikelyCredential(reason) {
		return errors.New("reason appears to contain credential material; describe it without the value")
	}
	if strings.TrimSpace(reason) == "" {
		return errors.New("reason must not be blank")
	}
	return nil
}

func validateCurrentCommandText(value string, minBytes, maxBytes int) error {
	if err := validateText(value, minBytes, maxBytes); err != nil {
		return err
	}
	for _, r := range value {
		if unicode.Is(unicode.Cf, r) || isUnicodeNoncharacter(r) {
			return errors.New("invisible format characters and noncharacters are not allowed")
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
	if r.Version != RequestVersionV1 {
		return errors.New("request is not a legacy capability request")
	}
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

func ValidateRequestAgainstProfile(r Request, profile CommandProfile) error {
	if r.Version != RequestVersion || r.ProfileID != profile.ID || r.ProfileVersion != profile.Version {
		return errors.New("request profile does not match")
	}
	return ValidateCommandProfile(profile)
}

func ValidateReceipt(r Receipt, now time.Time, maxLifetime time.Duration) error {
	if r.Version != ReceiptVersion && r.Version != ReceiptVersionV2 && r.Version != ReceiptVersionV1 {
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
	if !validReceiptDecision(r.Version, r.Decision) {
		return errors.New("invalid receipt decision")
	}
	if err := validateText(r.Reviewer, 1, 254); err != nil {
		return fmt.Errorf("reviewer: %w", err)
	}
	if r.Version == ReceiptVersion {
		if r.AdapterVersion != "" || r.ProfileID != ProfileGitHubCommandID || r.ProfileVersion != ProfileGitHubCommandVersion || !digestPattern.MatchString(r.PlanDigest) {
			return errors.New("invalid command receipt binding")
		}
	} else if r.AdapterVersion != AdapterGitHubAddCollaboratorV1 || r.ProfileID != "" || r.ProfileVersion != "" || r.PlanDigest != "" {
		return errors.New("invalid legacy receipt binding")
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

// ValidatePersistedReceipt validates a historical receipt against the stable
// protocol envelope while allowing an already-expired receipt to remain as
// durable audit history.
func ValidatePersistedReceipt(r Receipt) error {
	return validateAtExpiry(func(now time.Time) error {
		return ValidateReceipt(r, now, PersistedReceiptMaxLifetime)
	}, r.ExpiresAt)
}

func validReceiptDecision(version, decision string) bool {
	switch version {
	case ReceiptVersionV1:
		return decision == DecisionApproveForManualExecution || decision == DecisionDeny || decision == DecisionManuallyExecuted
	case ReceiptVersionV2, ReceiptVersion:
		return decision == DecisionApproveForExecution || decision == DecisionDeny || decision == DecisionExecuted
	default:
		return false
	}
}

func NextRequestState(current, decision string) (string, error) {
	switch {
	case current == "pending" && decision == DecisionApproveForManualExecution:
		return "approved", nil
	case current == "pending" && decision == DecisionDeny:
		return "denied", nil
	case current == "approved" && decision == DecisionManuallyExecuted:
		return "manually_executed", nil
	case current == "pending" && decision == DecisionApproveForExecution:
		return "approved_for_execution", nil
	case current == "approved_for_execution" && decision == DecisionApproveForExecution:
		// A failed/uncertain provider attempt needs a fresh explicit approval
		// receipt before an allowed retry. The requester has no provider-attempt
		// records, so this is its durable retry representation.
		return "approved_for_execution", nil
	case current == "approved_for_execution" && decision == DecisionExecuted:
		return "executed", nil
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

// validateAtExpiry selects a deterministic point inside the object lifetime,
// so the current validators still enforce all structural and time-window
// invariants without treating historical expiry as corruption. All protocol
// lifetimes have a one-minute minimum, making the one-second offset safe.
func validateAtExpiry(validate func(time.Time) error, expiresRaw string) error {
	expires, err := time.Parse(time.RFC3339, expiresRaw)
	if err != nil {
		return errors.New("invalid expiry timestamp")
	}
	return validate(expires.Add(-time.Second))
}

func validateText(value string, minBytes, maxBytes int) error {
	if len(value) < minBytes || len(value) > maxBytes || !utf8.ValidString(value) {
		return errors.New("length or UTF-8 is invalid")
	}
	for _, r := range value {
		if unicode.IsControl(r) || r >= 0x7f && r <= 0x9f || isBidirectionalControl(r) {
			return errors.New("control characters are not allowed")
		}
	}
	return nil
}

func isUnicodeNoncharacter(r rune) bool {
	return r >= 0xfdd0 && r <= 0xfdef || r <= utf8.MaxRune && r&0xfffe == 0xfffe
}

func isBidirectionalControl(r rune) bool {
	switch r {
	case '\u061c', '\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069':
		return true
	default:
		return false
	}
}
