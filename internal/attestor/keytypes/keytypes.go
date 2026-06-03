// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keytypes defines the attestor MVP key-type vocabulary and pure
// component-key handle construction.
package keytypes

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const (
	// AttestorComponentEd25519V1 is a raw Ed25519 component-signing key. It is
	// not an Algorand spending account and must not be accepted by /sign.
	AttestorComponentEd25519V1 = "aplane.attestor-component-ed25519.v1"

	// AttestedFalcon1024V1 is the MVP user-account key type whose LogicSig
	// verifies a Falcon-1024 user signature plus an attestor component
	// signature.
	AttestedFalcon1024V1 = "aplane.falcon1024-attested.v1"

	// AttestedEd25519V1 is an optional future account type. It is classified so
	// deny gates can fail closed even before implementation.
	AttestedEd25519V1 = "aplane.ed25519-attested.v1"

	ComponentKeyIDPrefix = "attkey_"

	componentKeyDomainV1 = "APLANE_COMPONENT_KEY_V1"
)

// IsAttestorComponentKeyType reports whether keyType names a component key
// that may only be used through /sign/component.
func IsAttestorComponentKeyType(keyType string) bool {
	return keyType == AttestorComponentEd25519V1
}

// IsAttestedAccountKeyType reports whether keyType names an attested spending
// account that requires the component signing and assembly flow.
func IsAttestedAccountKeyType(keyType string) bool {
	switch keyType {
	case AttestedFalcon1024V1, AttestedEd25519V1:
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

// ComponentKeyID returns the stable public handle for an attestor component key.
func ComponentKeyID(keyType string, publicKey []byte) (string, error) {
	if !IsAttestorComponentKeyType(keyType) {
		return "", fmt.Errorf("key type %q is not an attestor component key type", keyType)
	}
	if len(publicKey) == 0 {
		return "", fmt.Errorf("component public key is required")
	}
	if len(keyType) > 0xffff {
		return "", fmt.Errorf("key type is too long")
	}

	h := sha256.New()
	h.Write([]byte(componentKeyDomainV1))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(keyType)))
	h.Write(lenBuf[:])
	h.Write([]byte(keyType))
	h.Write(publicKey)
	return ComponentKeyIDPrefix + hex.EncodeToString(h.Sum(nil)), nil
}
