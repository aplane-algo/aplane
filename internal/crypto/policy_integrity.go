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
	// from an identity's current term key.
	PolicyIntegrityKeyLength = 32

	// NodeRoleIntegrityKeyLength is the byte length of node-role HMAC keys
	// derived from an identity's current term key.
	NodeRoleIntegrityKeyLength = 32

	policyIntegrityHKDFInfo   = "aplane policy integrity v1"
	nodeRoleIntegrityHKDFInfo = "aplane node role integrity v1"
)

// derivePolicyIntegrityKey derives the identity policy-integrity HMAC key
// from a term key.
//
// Callers reach this through Keyring.PolicyIntegrityKey. It stays here,
// unexported, as the reference the keyring's derivation is tested against:
// every sidecar already on disk was signed with its output.
func derivePolicyIntegrityKey(masterKey []byte) ([]byte, error) {
	return deriveIntegrityKey(masterKey, []byte(policyIntegrityHKDFInfo), PolicyIntegrityKeyLength, "policy")
}

// deriveNodeRoleIntegrityKey derives the node-role HMAC key from a term key.
// Callers reach this through Keyring.NodeRoleIntegrityKey.
func deriveNodeRoleIntegrityKey(masterKey []byte) ([]byte, error) {
	return deriveIntegrityKey(masterKey, []byte(nodeRoleIntegrityHKDFInfo), NodeRoleIntegrityKeyLength, "node role")
}

func deriveIntegrityKey(masterKey []byte, info []byte, length int, label string) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("master key is required")
	}
	reader := hkdf.New(sha256.New, masterKey, nil, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(reader, key); err != nil {
		ZeroBytes(key)
		return nil, fmt.Errorf("failed to derive %s integrity key: %w", label, err)
	}
	return key, nil
}
