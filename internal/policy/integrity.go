// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
)

const (
	PolicyIntegritySidecarVersion = 2
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
)

// IntegritySidecar is the JSON representation stored next to policy.yaml.
//
// The HMAC authenticates policy.yaml bytes only. Metadata fields in this
// sidecar are diagnostic unless explicitly checked by VerifyPolicyIntegrity.
type IntegritySidecar struct {
	Version       int    `json:"version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	IntegrityTerm int64  `json:"integrity_term"`
	HMAC          string `json:"hmac"`
	PolicySHA256  string `json:"policy_sha256,omitempty"`
	SignedAtUnix  int64  `json:"signed_at_unix,omitempty"`
	PolicyMTimeNS int64  `json:"policy_mtime_ns,omitempty"`
}

// PolicyIntegritySidecarPath returns the sidecar path for a policy file path.
func PolicyIntegritySidecarPath(policyPath string) string {
	return policyPath + ".hmac"
}

// SignPolicyIntegrity returns the sidecar for policyBytes using the keyring's
// current policy-integrity authority.
func SignPolicyIntegrity(policyBytes []byte, kr *apcrypto.Keyring, signedAt time.Time, policyMTimeNS int64) (*IntegritySidecar, error) {
	if kr == nil {
		return nil, policyIntegrityError(ErrPolicyIntegrityBadSidecar, "keyring is required")
	}
	if signedAt.IsZero() {
		signedAt = time.Now()
	}
	term, mac, err := kr.SignIntegrity(apcrypto.IntegrityDomainPolicy, policyBytes)
	if err != nil {
		return nil, policyIntegrityWrap(ErrPolicyIntegrityBadSidecar, err, "failed to sign policy integrity")
	}
	sum := sha256.Sum256(policyBytes)
	return &IntegritySidecar{
		Version:       PolicyIntegritySidecarVersion,
		Algorithm:     PolicyIntegrityAlgorithm,
		KeyID:         PolicyIntegrityKeyID,
		IntegrityTerm: term,
		HMAC:          mac,
		PolicySHA256:  hex.EncodeToString(sum[:]),
		SignedAtUnix:  signedAt.UTC().Unix(),
		PolicyMTimeNS: policyMTimeNS,
	}, nil
}

// VerifyPolicyIntegrity verifies sidecar security fields and HMAC against
// policyBytes. Diagnostic metadata such as PolicySHA256 and PolicyMTimeNS is
// not trusted and does not affect the verification decision.
func VerifyPolicyIntegrity(policyBytes []byte, sidecar *IntegritySidecar, kr *apcrypto.Keyring) error {
	if kr == nil {
		return policyIntegrityError(ErrPolicyIntegrityBadSidecar, "keyring is required")
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
	if sidecar.IntegrityTerm <= 0 {
		return policyIntegrityError(ErrPolicyIntegrityBadSidecar, "missing integrity_term")
	}
	if err := validateCanonicalPolicyHMAC(sidecar.HMAC); err != nil {
		return policyIntegrityWrap(ErrPolicyIntegrityBadSidecar, err, "invalid hmac encoding")
	}
	if err := kr.VerifyIntegrity(
		apcrypto.IntegrityDomainPolicy,
		policyBytes,
		sidecar.IntegrityTerm,
		sidecar.HMAC,
	); err != nil {
		return policyIntegrityWrap(ErrPolicyIntegrityMismatch, err, "HMAC verification failed")
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
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sidecar); err != nil {
		return nil, policyIntegrityWrap(ErrPolicyIntegrityBadSidecar, err, "failed to parse sidecar")
	}
	if err := requireJSONEOF(decoder); err != nil {
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

func validateCanonicalPolicyHMAC(encoded string) error {
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return err
	}
	if len(decoded) != sha256.Size || encoded != hex.EncodeToString(decoded) {
		return fmt.Errorf("expected canonical lowercase SHA-256 hex")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	switch err := decoder.Decode(&trailing); err {
	case io.EOF:
		return nil
	case nil:
		return fmt.Errorf("trailing data after JSON document")
	default:
		return fmt.Errorf("trailing data after JSON document: %w", err)
	}
}

func policyIntegrityError(kind error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%w: %w: %s", ErrPolicyIntegrity, kind, msg)
}

func policyIntegrityWrap(kind error, cause error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%w: %w: %s: %w", ErrPolicyIntegrity, kind, msg, cause)
}
