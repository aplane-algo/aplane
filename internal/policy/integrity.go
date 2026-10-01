// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/integritysidecar"
)

const (
	PolicyIntegritySidecarVersion = integritysidecar.Version
	PolicyIntegrityAlgorithm      = integritysidecar.Algorithm
	PolicyIntegrityKeyID          = "keystore-master-hkdf-v1"
)

var (
	ErrPolicyIntegrity               = errors.New("policy integrity check failed")
	ErrPolicyIntegrityMissingFile    = errors.New("policy file missing")
	ErrPolicyIntegrityUnreadable     = errors.New("policy file unreadable")
	ErrPolicyIntegrityMissingSidecar = errors.New("policy integrity sidecar missing")
	ErrPolicyIntegrityBadSidecar     = errors.New("policy integrity sidecar invalid")
	ErrPolicyIntegrityUnsupported    = errors.New("policy integrity sidecar unsupported")
	ErrPolicyIntegrityMismatch       = errors.New("policy integrity mismatch")
)

var policySidecar = integritysidecar.Spec{
	Domain: apcrypto.IntegrityDomainPolicy,
	KeyID:  PolicyIntegrityKeyID,
	Name:   "policy",
	Errors: integritysidecar.Errors{
		Check:       ErrPolicyIntegrity,
		Bad:         ErrPolicyIntegrityBadSidecar,
		Missing:     ErrPolicyIntegrityMissingSidecar,
		Unsupported: ErrPolicyIntegrityUnsupported,
		Mismatch:    ErrPolicyIntegrityMismatch,
	},
}

// IntegritySidecar is the JSON representation stored next to policy.yaml.
//
// The HMAC authenticates policy.yaml bytes only. Fields beyond the embedded
// security header are diagnostic.
type IntegritySidecar struct {
	integritysidecar.Header
	PolicySHA256 string `json:"policy_sha256,omitempty"`
	SignedAtUnix int64  `json:"signed_at_unix,omitempty"`
}

// PolicyIntegritySidecarPath returns the sidecar path for a policy file path.
func PolicyIntegritySidecarPath(policyPath string) string {
	return policyPath + ".hmac"
}

// SignPolicyIntegrity returns the sidecar for policyBytes using the keyring's
// current policy-integrity authority.
func SignPolicyIntegrity(policyBytes []byte, kr *apcrypto.Keyring, signedAt time.Time) (*IntegritySidecar, error) {
	header, err := policySidecar.Sign(policyBytes, kr)
	if err != nil {
		return nil, err
	}
	if signedAt.IsZero() {
		signedAt = time.Now()
	}
	return &IntegritySidecar{
		Header:       header,
		PolicySHA256: PolicySHA256(policyBytes),
		SignedAtUnix: signedAt.UTC().Unix(),
	}, nil
}

// VerifyPolicyIntegrity verifies sidecar security fields and HMAC against
// policyBytes. Diagnostic metadata such as PolicySHA256 and SignedAtUnix is
// not trusted and does not affect the verification decision.
func VerifyPolicyIntegrity(policyBytes []byte, sidecar *IntegritySidecar, kr *apcrypto.Keyring) error {
	var header *integritysidecar.Header
	if sidecar != nil {
		header = &sidecar.Header
	}
	return policySidecar.Verify(policyBytes, header, kr)
}

// MarshalPolicyIntegritySidecar encodes a sidecar with a trailing newline.
func MarshalPolicyIntegritySidecar(sidecar *IntegritySidecar) ([]byte, error) {
	if sidecar == nil {
		return nil, policyIntegrityError(ErrPolicyIntegrityBadSidecar, "missing sidecar data")
	}
	return policySidecar.Marshal(sidecar)
}

// ParsePolicyIntegritySidecar parses sidecar JSON. Security fields are
// validated by VerifyPolicyIntegrity.
func ParsePolicyIntegritySidecar(data []byte) (*IntegritySidecar, error) {
	var sidecar IntegritySidecar
	if err := policySidecar.Parse(data, &sidecar); err != nil {
		return nil, err
	}
	return &sidecar, nil
}

// LoadPolicyIntegritySidecar reads and parses a sidecar from disk.
func LoadPolicyIntegritySidecar(path string) (*IntegritySidecar, error) {
	var sidecar IntegritySidecar
	if err := policySidecar.Load(path, &sidecar); err != nil {
		return nil, err
	}
	return &sidecar, nil
}

// PolicySHA256 returns the hex SHA-256 digest of policyBytes for diagnostics.
func PolicySHA256(policyBytes []byte) string {
	sum := sha256.Sum256(policyBytes)
	return hex.EncodeToString(sum[:])
}

func policyIntegrityError(kind error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%w: %w: %s", ErrPolicyIntegrity, kind, msg)
}

func policyIntegrityWrap(kind error, cause error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%w: %w: %s: %w", ErrPolicyIntegrity, kind, msg, cause)
}
