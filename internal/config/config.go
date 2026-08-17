package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/donovan-yohan/airlock/internal/model"
)

const (
	maxConfigBytes      = 1 << 20
	maxTrustedPathBytes = 1024
)

type Requester struct {
	Listen               string `json:"listen"`
	StateDir             string `json:"state_dir"`
	TrustedPublicKeyFile string `json:"trusted_public_key_file"`
	RequestMaxTTL        string `json:"request_max_ttl"`
	CatalogMaxTTL        string `json:"catalog_max_ttl"`
	ReceiptMaxTTL        string `json:"receipt_max_ttl"`
}

type TrustedCapability struct {
	ID           string   `json:"id"`
	DisplayName  string   `json:"display_name"`
	Adapter      string   `json:"adapter"`
	Owner        string   `json:"owner"`
	Collaborator string   `json:"collaborator"`
	Permissions  []string `json:"permissions"`
}

type Trusted struct {
	Listen           string              `json:"listen"`
	StateDir         string              `json:"state_dir"`
	ControlSocket    string              `json:"control_socket"`
	PrivateKeyFile   string              `json:"private_key_file"`
	RequesterURL     string              `json:"requester_url"`
	GitHubCLIPath    string              `json:"github_cli_path"`
	GitHubConfigDir  string              `json:"github_config_dir"`
	ExecutionTimeout string              `json:"execution_timeout"`
	PollInterval     string              `json:"poll_interval"`
	RequestMaxTTL    string              `json:"request_max_ttl"`
	CatalogTTL       string              `json:"catalog_ttl"`
	ReceiptTTL       string              `json:"receipt_ttl"`
	AllowedLogins    []string            `json:"allowed_logins"`
	Capabilities     []TrustedCapability `json:"capabilities"`
}

func LoadRequester(path string) (Requester, error) {
	var cfg Requester
	if err := load(path, &cfg); err != nil {
		return cfg, err
	}
	base := filepath.Dir(path)
	cfg.StateDir = resolvePath(base, cfg.StateDir)
	cfg.TrustedPublicKeyFile = resolvePath(base, cfg.TrustedPublicKeyFile)
	if cfg.Listen == "" || cfg.StateDir == "" || cfg.TrustedPublicKeyFile == "" {
		return cfg, errors.New("listen, state_dir, and trusted_public_key_file are required")
	}
	if _, _, _, err := cfg.Durations(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Requester) Durations() (request, catalog, receipt time.Duration, err error) {
	request, err = boundedDuration("request_max_ttl", c.RequestMaxTTL, 15*time.Minute, time.Minute, time.Hour)
	if err != nil {
		return 0, 0, 0, err
	}
	catalog, err = boundedDuration("catalog_max_ttl", c.CatalogMaxTTL, time.Hour, time.Minute, 24*time.Hour)
	if err != nil {
		return 0, 0, 0, err
	}
	receipt, err = boundedDuration("receipt_max_ttl", c.ReceiptMaxTTL, 24*time.Hour, time.Minute, 7*24*time.Hour)
	return request, catalog, receipt, err
}

func LoadTrusted(path string) (Trusted, error) {
	var cfg Trusted
	if err := load(path, &cfg); err != nil {
		return cfg, err
	}
	base := filepath.Dir(path)
	// Execution config is handed to a child process, so unlike the other
	// repository-relative file settings it is normalized to an absolute path
	// before the strict direct-exec validation below.
	executionBase, err := filepath.Abs(base)
	if err != nil {
		return cfg, fmt.Errorf("resolve trusted execution config directory: %w", err)
	}
	cfg.StateDir = resolvePath(executionBase, cfg.StateDir)
	cfg.PrivateKeyFile = resolvePath(executionBase, cfg.PrivateKeyFile)
	cfg.GitHubConfigDir = resolvePath(executionBase, cfg.GitHubConfigDir)
	cfg.ControlSocket = resolvePath(executionBase, cfg.ControlSocket)
	if cfg.Listen == "" || cfg.StateDir == "" || cfg.ControlSocket == "" || cfg.PrivateKeyFile == "" || cfg.RequesterURL == "" || cfg.GitHubCLIPath == "" || cfg.GitHubConfigDir == "" || cfg.ExecutionTimeout == "" {
		return cfg, errors.New("listen, state_dir, control_socket, private_key_file, requester_url, github_cli_path, github_config_dir, and execution_timeout are required")
	}
	if _, _, _, _, err := cfg.Durations(); err != nil {
		return cfg, err
	}
	if err := validateRequesterURL(cfg.RequesterURL); err != nil {
		return cfg, err
	}
	if err := validateTrustedAbsolutePath("github_cli_path", cfg.GitHubCLIPath); err != nil {
		return cfg, err
	}
	if err := validateTrustedAbsolutePath("github_config_dir", cfg.GitHubConfigDir); err != nil {
		return cfg, err
	}
	if err := validateTrustedAbsolutePath("control_socket", cfg.ControlSocket); err != nil {
		return cfg, err
	}
	if err := validateControlSocketPath(cfg.StateDir, cfg.ControlSocket); err != nil {
		return cfg, err
	}
	if _, err := cfg.ExecutionDuration(); err != nil {
		return cfg, err
	}
	if len(cfg.AllowedLogins) == 0 {
		return cfg, errors.New("allowed_logins must not be empty")
	}
	if !sort.StringsAreSorted(cfg.AllowedLogins) {
		return cfg, errors.New("allowed_logins must be sorted")
	}
	seenLogins := map[string]bool{}
	for _, login := range cfg.AllowedLogins {
		if strings.TrimSpace(login) != login || login == "" || len(login) > 254 || strings.ContainsAny(login, "\r\n\x00") {
			return cfg, errors.New("allowed_logins contains an invalid login")
		}
		if seenLogins[login] {
			return cfg, errors.New("allowed_logins contains a duplicate")
		}
		seenLogins[login] = true
	}
	if len(cfg.Capabilities) == 0 || len(cfg.Capabilities) > model.MaxCapabilities {
		return cfg, errors.New("capability count out of bounds")
	}
	ids := make([]string, 0, len(cfg.Capabilities))
	for _, capability := range cfg.Capabilities {
		if capability.Adapter != model.AdapterGitHubAddCollaboratorV1 {
			return cfg, fmt.Errorf("capability %q uses an unsupported adapter", capability.ID)
		}
		if !strings.EqualFold(capability.ID, "github:"+capability.Owner) {
			return cfg, fmt.Errorf("capability %q must identify its configured GitHub owner", capability.ID)
		}
		candidate := capability.CatalogCapability()
		if err := model.ValidateCapability(candidate); err != nil {
			return cfg, fmt.Errorf("capability %q: %w", capability.ID, err)
		}
		ids = append(ids, capability.ID)
	}
	if !sort.StringsAreSorted(ids) {
		return cfg, errors.New("capabilities must be sorted by id")
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			return cfg, errors.New("capabilities contains a duplicate id")
		}
	}
	return cfg, nil
}

func validateControlSocketPath(stateDir, socket string) error {
	absStateDir, err := filepath.Abs(stateDir)
	if err != nil {
		return fmt.Errorf("resolve state_dir for control_socket: %w", err)
	}
	relative, err := filepath.Rel(filepath.Clean(absStateDir), socket)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("control_socket must remain inside state_dir")
	}
	if filepath.Dir(socket) != filepath.Clean(absStateDir) {
		return errors.New("control_socket must be a direct child of state_dir")
	}
	return nil
}

// ExecutionDuration is deliberately separate from the polling/receipt tuple:
// execution has a tighter bound and must never silently inherit a default.
func (c Trusted) ExecutionDuration() (time.Duration, error) {
	return boundedDuration("execution_timeout", c.ExecutionTimeout, 0, time.Second, 5*time.Minute)
}

func (c Trusted) Durations() (poll, request, catalog, receipt time.Duration, err error) {
	poll, err = boundedDuration("poll_interval", c.PollInterval, time.Second, 100*time.Millisecond, time.Minute)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	request, err = boundedDuration("request_max_ttl", c.RequestMaxTTL, 15*time.Minute, time.Minute, time.Hour)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	catalog, err = boundedDuration("catalog_ttl", c.CatalogTTL, time.Hour, time.Minute, 24*time.Hour)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	receipt, err = boundedDuration("receipt_ttl", c.ReceiptTTL, 24*time.Hour, time.Minute, 7*24*time.Hour)
	return poll, request, catalog, receipt, err
}

func (c TrustedCapability) CatalogCapability() model.Capability {
	permissions := append([]string(nil), c.Permissions...)
	return model.Capability{
		ID: c.ID, DisplayName: c.DisplayName,
		Actions: []string{model.ActionGitHubAddCollaborator},
		Constraints: model.GitHubConstraints{
			Owner: c.Owner, Collaborator: c.Collaborator, Permissions: permissions,
		},
	}
}

func load(path string, destination any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	limited := io.LimitReader(f, maxConfigBytes+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(b) > maxConfigBytes {
		return errors.New("config file exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("config must contain one JSON object")
	}
	return nil
}

func boundedDuration(name, raw string, fallback, minimum, maximum time.Duration) (time.Duration, error) {
	if raw == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be between %s and %s", name, minimum, maximum)
	}
	return parsed, nil
}

func resolvePath(base, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(filepath.Join(base, value))
}

func validateTrustedAbsolutePath(name, value string) error {
	if value == "" || len(value) > maxTrustedPathBytes || !utf8.ValidString(value) || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) {
		return fmt.Errorf("%s must be a clean non-root absolute path", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s must be a clean non-root absolute path", name)
		}
	}
	return nil
}

func validateRequesterURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("requester_url must be an absolute http or https URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return errors.New("requester_url must not contain credentials, query, fragment, or path")
	}
	return nil
}
