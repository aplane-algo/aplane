// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keytypes defines the attestor MVP key-type vocabulary and pure
// component-key handle construction.
package keytypes

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

const (
	// AttestorComponentEd25519V1 is a raw Ed25519 component-signing key. It is
	// not an Algorand spending account and must not be accepted by /sign.
	AttestorComponentEd25519V1 = "aplane.attestor-ed25519.v1"

	// AttestorComponentFalcon1024V1 is a raw Falcon-1024 component-signing key.
	// It is not an Algorand spending account and must not be accepted by /sign.
	AttestorComponentFalcon1024V1 = "aplane.attestor-falcon1024.v1"

	// AttestedFalcon1024V1 is the MVP user-account key type whose LogicSig
	// verifies a Falcon-1024 user signature plus an Ed25519 attestor component
	// signature.
	AttestedFalcon1024V1 = "aplane.falcon1024-att-ed25519.v1"

	// ParameterAttestorPublicKey is the durable creation parameter that records
	// the attestor Ed25519 public key embedded in an attested account LogicSig.
	ParameterAttestorPublicKey = "attestor_public_key"

	// ComponentKeySelectorPrefix marks APlane attestor component-key selectors.
	ComponentKeySelectorPrefix = "a_"
)

// IsAttestorComponentKeyType reports whether keyType names a component key
// that may only be used through /sign/component.
func IsAttestorComponentKeyType(keyType string) bool {
	switch keyType {
	case AttestorComponentEd25519V1, AttestorComponentFalcon1024V1:
		return true
	default:
		return false
	}
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
// key. Selectors are a_ plus lower-case SHA-256 of the canonical public key
// bytes, independent of the component key family.
func ComponentKeySelector(keyType string, publicKey []byte) (string, error) {
	if !IsAttestorComponentKeyType(keyType) {
		return "", fmt.Errorf("key type %q is not an attestor component key type", keyType)
	}
	wantSize, ok := ComponentPublicKeySize(keyType)
	if !ok {
		return "", fmt.Errorf("key type %q is not an attestor component key type", keyType)
	}
	if len(publicKey) != wantSize {
		return "", fmt.Errorf("component public key length %d invalid (expected %d bytes)", len(publicKey), wantSize)
	}

	sum := sha256.Sum256(publicKey)
	return ComponentKeySelectorPrefix + hex.EncodeToString(sum[:]), nil
}

// NormalizeComponentKeySelector validates and canonicalizes a component-key
// selector. Selectors must already be canonical a_<lower-hex-sha256>.
func NormalizeComponentKeySelector(selector string) (string, error) {
	raw := strings.TrimSpace(selector)
	if raw == "" {
		return "", fmt.Errorf("component key selector is required")
	}
	if !strings.HasPrefix(raw, ComponentKeySelectorPrefix) {
		return "", fmt.Errorf("component key selector must start with %q", ComponentKeySelectorPrefix)
	}
	hashHex := strings.TrimPrefix(raw, ComponentKeySelectorPrefix)
	decoded, err := hex.DecodeString(hashHex)
	if err != nil {
		return "", fmt.Errorf("component key selector hash must be hex: %w", err)
	}
	if len(decoded) != sha256.Size {
		return "", fmt.Errorf("component key selector hash length %d invalid (expected %d bytes)", len(decoded), sha256.Size)
	}
	if hex.EncodeToString(decoded) != hashHex {
		return "", fmt.Errorf("component key selector hash must be lowercase hex")
	}
	return raw, nil
}

// IsComponentKeySelector reports whether selector is a syntactically valid
// attestor component-key selector.
func IsComponentKeySelector(selector string) bool {
	_, err := NormalizeComponentKeySelector(selector)
	return err == nil
}

// ComponentPublicKeySize returns the public key byte size for a component key
// type.
func ComponentPublicKeySize(keyType string) (int, bool) {
	switch keyType {
	case AttestorComponentEd25519V1:
		return ed25519.PublicKeySize, true
	case AttestorComponentFalcon1024V1:
		return falconfamily.PublicKeySize, true
	default:
		return 0, false
	}
}

// ComponentPrivateKeySize returns the private key byte size for a component key
// type.
func ComponentPrivateKeySize(keyType string) (int, bool) {
	switch keyType {
	case AttestorComponentEd25519V1:
		return ed25519.PrivateKeySize, true
	case AttestorComponentFalcon1024V1:
		return falconfamily.PrivateKeySize, true
	default:
		return 0, false
	}
}
