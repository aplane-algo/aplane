// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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

	integrityKeyLength = 32

	policyIntegrityHKDFInfo         = "aplane policy integrity v1"
	nodeRoleIntegrityHKDFInfo       = "aplane node role integrity v1"
	generationSealIntegrityHKDFInfo = "aplane generation seal integrity v1"
)

// IntegrityDomain selects one independently derived per-term HMAC key.
// Callers receive MACs, never the derived key bytes.
type IntegrityDomain string

const (
	IntegrityDomainPolicy         IntegrityDomain = "policy"
	IntegrityDomainNodeRole       IntegrityDomain = "node-role"
	IntegrityDomainGenerationSeal IntegrityDomain = "generation-seal"
)

// SignIntegrity authenticates payload under the current term's key for
// domain. The returned term must be stored beside the MAC.
func (kr *Keyring) SignIntegrity(domain IntegrityDomain, payload []byte) (int64, string, error) {
	if kr == nil || len(kr.terms) == 0 {
		return 0, "", fmt.Errorf("keyring is not open")
	}
	term := kr.currentTerm
	key, err := kr.integrityKeyForTerm(domain, term)
	if err != nil {
		return 0, "", err
	}
	defer ZeroBytes(key)
	return term, computeIntegrityMAC(payload, key), nil
}

// VerifyIntegrity authenticates payload under the named term only when that
// term has current-state read authority. Today that is exactly the current
// term; the pending transition later extends this check to its retiring term.
func (kr *Keyring) VerifyIntegrity(domain IntegrityDomain, payload []byte, term int64, encodedMAC string) error {
	if kr == nil || len(kr.terms) == 0 {
		return fmt.Errorf("keyring is not open")
	}
	if term != kr.currentTerm {
		return fmt.Errorf("term %d is not authorized for current integrity state", term)
	}
	got, err := hex.DecodeString(encodedMAC)
	if err != nil || len(got) != sha256.Size || hex.EncodeToString(got) != encodedMAC {
		return fmt.Errorf("integrity MAC must be %d lowercase hexadecimal characters", sha256.Size*2)
	}
	key, err := kr.integrityKeyForTerm(domain, term)
	if err != nil {
		return err
	}
	defer ZeroBytes(key)
	expected := hmac.New(sha256.New, key)
	_, _ = expected.Write(payload)
	if !hmac.Equal(expected.Sum(nil), got) {
		return fmt.Errorf("integrity MAC mismatch")
	}
	return nil
}

func (kr *Keyring) integrityKeyForTerm(domain IntegrityDomain, term int64) ([]byte, error) {
	masterKey, ok := kr.terms[term]
	if !ok {
		return nil, fmt.Errorf("keyring has no key for term %d", term)
	}
	var info string
	switch domain {
	case IntegrityDomainPolicy:
		info = policyIntegrityHKDFInfo
	case IntegrityDomainNodeRole:
		info = nodeRoleIntegrityHKDFInfo
	case IntegrityDomainGenerationSeal:
		info = generationSealIntegrityHKDFInfo
	default:
		return nil, fmt.Errorf("unknown integrity domain %q", domain)
	}
	return deriveIntegrityKey(masterKey, []byte(info), integrityKeyLength, string(domain))
}

func computeIntegrityMAC(payload, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// derivePolicyIntegrityKey derives the identity policy-integrity HMAC key
// from a term key.
//
// It stays unexported as the reference the keyring's confined integrity
// operations are tested against.
func derivePolicyIntegrityKey(masterKey []byte) ([]byte, error) {
	return deriveIntegrityKey(masterKey, []byte(policyIntegrityHKDFInfo), PolicyIntegrityKeyLength, "policy")
}

// deriveNodeRoleIntegrityKey derives the node-role HMAC key from a term key.
// It remains confined to this package.
func deriveNodeRoleIntegrityKey(masterKey []byte) ([]byte, error) {
	return deriveIntegrityKey(masterKey, []byte(nodeRoleIntegrityHKDFInfo), NodeRoleIntegrityKeyLength, "node role")
}

func deriveIntegrityKey(masterKey []byte, info []byte, length int, label string) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("a term key is required")
	}
	reader := hkdf.New(sha256.New, masterKey, nil, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(reader, key); err != nil {
		ZeroBytes(key)
		return nil, fmt.Errorf("failed to derive %s integrity key: %w", label, err)
	}
	return key, nil
}
