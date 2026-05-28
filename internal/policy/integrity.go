// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
)

const (
	PolicyIntegritySidecarVersion = 1
	PolicyIntegrityAlgorithm      = "hmac-sha256"
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
	ErrPolicyIntegrityInvalidKey     = errors.New("policy integrity key invalid")
)

// IntegritySidecar is the JSON representation stored next to policy.yaml.
//
// The HMAC authenticates policy.yaml bytes only. Metadata fields in this
// sidecar are diagnostic unless explicitly checked by VerifyPolicyIntegrity.
type IntegritySidecar struct {
	Version       int    `json:"version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	HMAC          string `json:"hmac"`
	PolicySHA256  string `json:"policy_sha256,omitempty"`
	SignedAtUnix  int64  `json:"signed_at_unix,omitempty"`
	PolicyMTimeNS int64  `json:"policy_mtime_ns,omitempty"`
}

// PolicyIntegritySidecarPath returns the sidecar path for a policy file path.
func PolicyIntegritySidecarPath(policyPath string) string {
	return policyPath + ".hmac"
}

// SignPolicyIntegrity returns the sidecar for policyBytes using key.
func SignPolicyIntegrity(policyBytes, key []byte, signedAt time.Time, policyMTimeNS int64) (*IntegritySidecar, error) {
	if err := validatePolicyIntegrityKey(key); err != nil {
		return nil, err
	}
	if signedAt.IsZero() {
		signedAt = time.Now()
	}
	sum := sha256.Sum256(policyBytes)
	return &IntegritySidecar{
		Version:       PolicyIntegritySidecarVersion,
		Algorithm:     PolicyIntegrityAlgorithm,
		KeyID:         PolicyIntegrityKeyID,
		HMAC:          computePolicyHMAC(policyBytes, key),
		PolicySHA256:  hex.EncodeToString(sum[:]),
		SignedAtUnix:  signedAt.UTC().Unix(),
		PolicyMTimeNS: policyMTimeNS,
	}, nil
}

// VerifyPolicyIntegrity verifies sidecar security fields and HMAC against
// policyBytes. Diagnostic metadata such as PolicySHA256 and PolicyMTimeNS is
// not trusted and does not affect the verification decision.
func VerifyPolicyIntegrity(policyBytes []byte, sidecar *IntegritySidecar, key []byte) error {
	if err := validatePolicyIntegrityKey(key); err != nil {
		return err
	}
	if sidecar == nil {
		return policyIntegrityError(ErrPolicyIntegrityBadSidecar, "missing sidecar data")
	}
	if sidecar.Version != PolicyIntegritySidecarVersion {
		return policyIntegrityError(ErrPolicyIntegrityUnsupported, "version %d", sidecar.Version)
	}
	if sidecar.Algorithm != PolicyIntegrityAlgorithm {
		return policyIntegrityError(ErrPolicyIntegrityUnsupported, "algorithm %q", sidecar.Algorithm)
	}
	if sidecar.KeyID != PolicyIntegrityKeyID {
		return policyIntegrityError(ErrPolicyIntegrityUnsupported, "key_id %q", sidecar.KeyID)
	}

	got, err := hex.DecodeString(sidecar.HMAC)
	if err != nil {
		return policyIntegrityWrap(ErrPolicyIntegrityBadSidecar, err, "invalid hmac encoding")
	}
	expectedHex := computePolicyHMAC(policyBytes, key)
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		return policyIntegrityWrap(ErrPolicyIntegrityBadSidecar, err, "internal hmac encoding failure")
	}
	if !hmac.Equal(expected, got) {
		return policyIntegrityError(ErrPolicyIntegrityMismatch, "hmac mismatch")
	}
	return nil
}

// MarshalPolicyIntegritySidecar encodes a sidecar with a trailing newline.
func MarshalPolicyIntegritySidecar(sidecar *IntegritySidecar) ([]byte, error) {
	if sidecar == nil {
		return nil, policyIntegrityError(ErrPolicyIntegrityBadSidecar, "missing sidecar data")
	}
	data, err := json.MarshalIndent(sidecar, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy integrity sidecar: %w", err)
	}
	return append(data, '\n'), nil
}

// ParsePolicyIntegritySidecar parses sidecar JSON. Security fields are
// validated by VerifyPolicyIntegrity.
func ParsePolicyIntegritySidecar(data []byte) (*IntegritySidecar, error) {
	var sidecar IntegritySidecar
	if err := json.Unmarshal(data, &sidecar); err != nil {
		return nil, policyIntegrityWrap(ErrPolicyIntegrityBadSidecar, err, "failed to parse sidecar")
	}
	return &sidecar, nil
}

// LoadPolicyIntegritySidecar reads and parses a sidecar from disk.
func LoadPolicyIntegritySidecar(path string) (*IntegritySidecar, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, policyIntegrityWrap(ErrPolicyIntegrityMissingSidecar, err, "sidecar %s", path)
		}
		return nil, policyIntegrityWrap(ErrPolicyIntegrityBadSidecar, err, "failed to read sidecar %s", path)
	}
	return ParsePolicyIntegritySidecar(data)
}

// PolicySHA256 returns the hex SHA-256 digest of policyBytes for diagnostics.
func PolicySHA256(policyBytes []byte) string {
	sum := sha256.Sum256(policyBytes)
	return hex.EncodeToString(sum[:])
}

func computePolicyHMAC(policyBytes, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(policyBytes)
	return hex.EncodeToString(mac.Sum(nil))
}

func validatePolicyIntegrityKey(key []byte) error {
	if len(key) != apcrypto.PolicyIntegrityKeyLength {
		return policyIntegrityError(ErrPolicyIntegrityInvalidKey, "expected %d bytes, got %d", apcrypto.PolicyIntegrityKeyLength, len(key))
	}
	return nil
}

func policyIntegrityError(kind error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%w: %w: %s", ErrPolicyIntegrity, kind, msg)
}

func policyIntegrityWrap(kind error, cause error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%w: %w: %s: %w", ErrPolicyIntegrity, kind, msg, cause)
}
