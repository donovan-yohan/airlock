package model

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	CatalogVersion = "airlock.catalog/v1"
	RequestVersion = "airlock.request/v1"
	// ReceiptVersion is emitted by the trusted executor. ReceiptVersionV1 is
	// retained only so requester and trusted recovery can read already-durable
	// manual-workflow receipts.
	ReceiptVersionV1 = "airlock.receipt/v1"
	ReceiptVersion   = "airlock.receipt/v2"

	ActionGitHubAddCollaborator    = "github.repo.add_collaborator"
	AdapterGitHubAddCollaboratorV1 = "github.repo.add_collaborator/v1"

	DecisionApproveForManualExecution = "approved_for_manual_execution"
	DecisionManuallyExecuted          = "manually_executed"
	DecisionApproveForExecution       = "approved_for_execution"
	DecisionExecuted                  = "executed"
	DecisionDeny                      = "denied"

	// Kept as source compatibility names for callers that construct historical
	// v1 receipts. New trusted code must use the explicit v2 names above.
	DecisionApprove = DecisionApproveForManualExecution
	DecisionExecute = DecisionManuallyExecuted
)

type GitHubConstraints struct {
	Owner        string   `json:"owner"`
	Collaborator string   `json:"collaborator"`
	Permissions  []string `json:"permissions"`
}

type Capability struct {
	ID          string            `json:"id"`
	DisplayName string            `json:"display_name"`
	Actions     []string          `json:"actions"`
	Constraints GitHubConstraints `json:"constraints"`
}

type Catalog struct {
	Version          string       `json:"version"`
	IssuedAt         string       `json:"issued_at"`
	ExpiresAt        string       `json:"expires_at"`
	TrustedPublicKey string       `json:"trusted_public_key"`
	Capabilities     []Capability `json:"capabilities"`
	Signature        string       `json:"signature"`
}

type Request struct {
	Version      string            `json:"version"`
	ID           string            `json:"id"`
	CapabilityID string            `json:"capability_id"`
	Action       string            `json:"action"`
	Arguments    map[string]string `json:"arguments"`
	Reason       string            `json:"reason"`
	CreatedAt    string            `json:"created_at"`
	ExpiresAt    string            `json:"expires_at"`
	Nonce        string            `json:"nonce"`
	Digest       string            `json:"digest"`
}

type Receipt struct {
	Version        string `json:"version"`
	ID             string `json:"id"`
	RequestID      string `json:"request_id"`
	RequestDigest  string `json:"request_digest"`
	Decision       string `json:"decision"`
	Reviewer       string `json:"reviewer"`
	AdapterVersion string `json:"adapter_version"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"`
	Evidence       string `json:"evidence,omitempty"`
	Signature      string `json:"signature"`
}

type catalogPayload struct {
	Version          string       `json:"version"`
	IssuedAt         string       `json:"issued_at"`
	ExpiresAt        string       `json:"expires_at"`
	TrustedPublicKey string       `json:"trusted_public_key"`
	Capabilities     []Capability `json:"capabilities"`
}

type requestPayload struct {
	Version      string            `json:"version"`
	ID           string            `json:"id"`
	CapabilityID string            `json:"capability_id"`
	Action       string            `json:"action"`
	Arguments    map[string]string `json:"arguments"`
	Reason       string            `json:"reason"`
	CreatedAt    string            `json:"created_at"`
	ExpiresAt    string            `json:"expires_at"`
	Nonce        string            `json:"nonce"`
}

type receiptPayload struct {
	Version        string `json:"version"`
	ID             string `json:"id"`
	RequestID      string `json:"request_id"`
	RequestDigest  string `json:"request_digest"`
	Decision       string `json:"decision"`
	Reviewer       string `json:"reviewer"`
	AdapterVersion string `json:"adapter_version"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"`
	Evidence       string `json:"evidence,omitempty"`
}

func CatalogSigningBytes(c Catalog) ([]byte, error) {
	return json.Marshal(catalogPayload{
		Version: c.Version, IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt,
		TrustedPublicKey: c.TrustedPublicKey, Capabilities: c.Capabilities,
	})
}

func RequestSigningBytes(r Request) ([]byte, error) {
	return json.Marshal(requestPayload{
		Version: r.Version, ID: r.ID, CapabilityID: r.CapabilityID, Action: r.Action,
		Arguments: r.Arguments, Reason: r.Reason, CreatedAt: r.CreatedAt,
		ExpiresAt: r.ExpiresAt, Nonce: r.Nonce,
	})
}

func ReceiptSigningBytes(r Receipt) ([]byte, error) {
	return json.Marshal(receiptPayload{
		Version: r.Version, ID: r.ID, RequestID: r.RequestID,
		RequestDigest: r.RequestDigest, Decision: r.Decision, Reviewer: r.Reviewer,
		AdapterVersion: r.AdapterVersion, CreatedAt: r.CreatedAt,
		ExpiresAt: r.ExpiresAt, Evidence: r.Evidence,
	})
}

func SetRequestDigest(r *Request) error {
	b, err := RequestSigningBytes(*r)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	r.Digest = hex.EncodeToString(sum[:])
	return nil
}

func VerifyRequestDigest(r Request) error {
	provided, err := hex.DecodeString(r.Digest)
	if err != nil || len(provided) != sha256.Size {
		return errors.New("invalid request digest encoding")
	}
	b, err := RequestSigningBytes(r)
	if err != nil {
		return fmt.Errorf("canonicalize request: %w", err)
	}
	expected := sha256.Sum256(b)
	if subtle.ConstantTimeCompare(provided, expected[:]) != 1 {
		return errors.New("request digest mismatch")
	}
	return nil
}

func SignCatalog(c *Catalog, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid Ed25519 private key")
	}
	pub := key.Public().(ed25519.PublicKey)
	c.TrustedPublicKey = base64.RawStdEncoding.EncodeToString(pub)
	b, err := CatalogSigningBytes(*c)
	if err != nil {
		return err
	}
	c.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, b))
	return nil
}

func VerifyCatalogSignature(c Catalog, expected ed25519.PublicKey) error {
	if len(expected) != ed25519.PublicKeySize {
		return errors.New("invalid expected Ed25519 public key")
	}
	advertised, err := base64.RawStdEncoding.DecodeString(c.TrustedPublicKey)
	if err != nil || len(advertised) != ed25519.PublicKeySize {
		return errors.New("invalid catalog public key")
	}
	if subtle.ConstantTimeCompare(advertised, expected) != 1 {
		return errors.New("catalog public key does not match configured trust root")
	}
	sig, err := base64.RawStdEncoding.DecodeString(c.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid catalog signature encoding")
	}
	b, err := CatalogSigningBytes(c)
	if err != nil {
		return err
	}
	if !ed25519.Verify(expected, b, sig) {
		return errors.New("invalid catalog signature")
	}
	return nil
}

func SignReceipt(r *Receipt, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid Ed25519 private key")
	}
	b, err := ReceiptSigningBytes(*r)
	if err != nil {
		return err
	}
	r.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, b))
	return nil
}

func VerifyReceiptSignature(r Receipt, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	sig, err := base64.RawStdEncoding.DecodeString(r.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid receipt signature encoding")
	}
	b, err := ReceiptSigningBytes(r)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, b, sig) {
		return errors.New("invalid receipt signature")
	}
	return nil
}

func NewRandom(prefix string, bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func Timestamp(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}
