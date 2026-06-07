// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keytypes defines the attestor MVP key-type vocabulary and pure
// component-key handle construction.
package keytypes

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"strings"

	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

const (
	// AttestorComponentEd25519V1 is a raw Ed25519 component-signing key. It is
	// not an Algorand spending account and must not be accepted by /sign.
	AttestorComponentEd25519V1 = "aplane.sen-ed25519.v1"

	// AttestorComponentFalcon1024V1 is a raw Falcon-1024 component-signing key.
	// It is not an Algorand spending account and must not be accepted by /sign.
	AttestorComponentFalcon1024V1 = "aplane.sen-falcon1024.v1"

	// AttestedFalcon1024AttEd25519V1 is the user-account key type whose LogicSig
	// verifies a Falcon-1024 user signature plus an Ed25519 attestor component
	// signature.
	AttestedFalcon1024AttEd25519V1 = "aplane.falcon1024-sen-ed25519.v1"

	// AttestedFalcon1024AttFalcon1024V1 is the user-account key type whose
	// LogicSig verifies a Falcon-1024 user signature plus a Falcon-1024
	// attestor component signature.
	AttestedFalcon1024AttFalcon1024V1 = "aplane.falcon1024-sen-falcon1024.v1"

	// AttestedFalcon1024V1 is a Go-level compatibility alias for the canonical
	// Ed25519-attestor Falcon account key type.
	AttestedFalcon1024V1 = AttestedFalcon1024AttEd25519V1

	// ParameterAttestorPublicKey is the durable creation parameter that records
	// the attestor public key embedded in an attested account LogicSig.
	ParameterAttestorPublicKey = "attestor_public_key"

	// ComponentKeySelectorLength is the length of a canonical attestor
	// component-key selector. It matches the visual shape of Algorand
	// transaction IDs, but it is shorter than an Algorand address and must not
	// be treated as one.
	ComponentKeySelectorLength = 52

	componentKeySelectorDomain = "APLANE_COMPONENT_KEY_V1"
)

var componentKeySelectorEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

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
	switch keyType {
	case AttestedFalcon1024AttEd25519V1, AttestedFalcon1024AttFalcon1024V1:
		return true
	default:
		return false
	}
}

// IsAttestorMVPKeyType reports whether keyType is any key type reserved by the
// attestor MVP.
func IsAttestorMVPKeyType(keyType string) bool {
	return IsAttestorComponentKeyType(keyType) || IsAttestedAccountKeyType(keyType)
}

// AttestorComponentKeyTypeForAttestedAccount returns the attestor component
// key type embedded by an attested account key type.
func AttestorComponentKeyTypeForAttestedAccount(keyType string) (string, bool) {
	switch keyType {
	case AttestedFalcon1024AttEd25519V1:
		return AttestorComponentEd25519V1, true
	case AttestedFalcon1024AttFalcon1024V1:
		return AttestorComponentFalcon1024V1, true
	default:
		return "", false
	}
}

// ComponentKeySelector returns the canonical selector for an attestor component
// key. Selectors are uppercase base32-no-padding SHA-512/256 digests over a
// domain-separated key-type/public-key tuple, independent of the component key
// family.
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

	h := sha512.New512_256()
	_, _ = h.Write([]byte(componentKeySelectorDomain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(keyType))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(publicKey)
	return componentKeySelectorEncoding.EncodeToString(h.Sum(nil)), nil
}

// NormalizeComponentKeySelector validates and canonicalizes a component-key
// selector. Selectors must already be canonical 52-character uppercase base32
// values with no padding.
func NormalizeComponentKeySelector(selector string) (string, error) {
	raw := strings.TrimSpace(selector)
	if raw == "" {
		return "", fmt.Errorf("component key selector is required")
	}
	if len(raw) != ComponentKeySelectorLength {
		return "", fmt.Errorf("component key selector length %d invalid (expected %d characters)", len(raw), ComponentKeySelectorLength)
	}
	decoded, err := componentKeySelectorEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("component key selector must be uppercase base32 without padding: %w", err)
	}
	if len(decoded) != sha512.Size256 {
		return "", fmt.Errorf("component key selector digest length %d invalid (expected %d bytes)", len(decoded), sha512.Size256)
	}
	if componentKeySelectorEncoding.EncodeToString(decoded) != raw {
		return "", fmt.Errorf("component key selector must be canonical uppercase base32 without padding")
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
