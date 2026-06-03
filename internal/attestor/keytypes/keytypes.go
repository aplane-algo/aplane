// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keytypes defines the attestor MVP key-type vocabulary and pure
// component-key handle construction.
package keytypes

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// AttestorComponentEd25519V1 is a raw Ed25519 component-signing key. It is
	// not an Algorand spending account and must not be accepted by /sign.
	AttestorComponentEd25519V1 = "aplane.attestor-ed25519.v1"

	// AttestedFalcon1024V1 is the MVP user-account key type whose LogicSig
	// verifies a Falcon-1024 user signature plus an attestor component
	// signature.
	AttestedFalcon1024V1 = "aplane.falcon1024-attested.v1"
)

// IsAttestorComponentKeyType reports whether keyType names a component key
// that may only be used through /sign/component.
func IsAttestorComponentKeyType(keyType string) bool {
	return keyType == AttestorComponentEd25519V1
}

// IsAttestedAccountKeyType reports whether keyType names an attested spending
// account that requires the component signing and assembly flow.
func IsAttestedAccountKeyType(keyType string) bool {
	return keyType == AttestedFalcon1024V1
}

// IsAttestorMVPKeyType reports whether keyType is any key type reserved by the
// attestor MVP.
func IsAttestorMVPKeyType(keyType string) bool {
	return IsAttestorComponentKeyType(keyType) || IsAttestedAccountKeyType(keyType)
}

// ComponentKeySelector returns the canonical selector for an attestor component
// key. Selectors are lower-case Ed25519 public-key hex.
func ComponentKeySelector(keyType string, publicKey []byte) (string, error) {
	if !IsAttestorComponentKeyType(keyType) {
		return "", fmt.Errorf("key type %q is not an attestor component key type", keyType)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("component public key length %d invalid (expected %d bytes)", len(publicKey), ed25519.PublicKeySize)
	}

	return hex.EncodeToString(publicKey), nil
}

// NormalizeComponentKeySelector validates and canonicalizes a component-key
// selector. It accepts an optional 0x prefix and upper-case hex on input.
func NormalizeComponentKeySelector(selector string) (string, error) {
	raw := strings.TrimSpace(selector)
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")
	if raw == "" {
		return "", fmt.Errorf("component key selector is required")
	}
	publicKey, err := hex.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("component key selector must be hex: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("component key selector length %d invalid (expected %d bytes)", len(publicKey), ed25519.PublicKeySize)
	}
	return hex.EncodeToString(publicKey), nil
}

// IsComponentKeySelector reports whether selector is a syntactically valid
// attestor component-key selector.
func IsComponentKeySelector(selector string) bool {
	_, err := NormalizeComponentKeySelector(selector)
	return err == nil
}
