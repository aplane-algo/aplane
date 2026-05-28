// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// PolicyIntegrityKeyLength is the byte length of policy HMAC keys derived
	// from an identity keystore master key.
	PolicyIntegrityKeyLength = 32

	policyIntegrityHKDFInfo = "aplane policy integrity v1"
)

// DerivePolicyIntegrityKey derives the identity policy-integrity HMAC key from
// a keystore master key. The caller owns the returned key and should zero it
// after use.
func DerivePolicyIntegrityKey(masterKey []byte) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("master key is required")
	}
	reader := hkdf.New(sha256.New, masterKey, nil, []byte(policyIntegrityHKDFInfo))
	key := make([]byte, PolicyIntegrityKeyLength)
	if _, err := io.ReadFull(reader, key); err != nil {
		ZeroBytes(key)
		return nil, fmt.Errorf("failed to derive policy integrity key: %w", err)
	}
	return key, nil
}
