// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package witness owns the role-neutral witness-key vocabulary and identity
// derivation. It is a leaf package so key classification is available without
// provider or algorithm-family registration.
package witness

import (
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/falconparams"
)

const (
	// Falcon1024V1 is a non-spending Falcon-1024 witness key. Enrollment and
	// custody determine whether an instance serves as a sentry or contract
	// admin; one keypair must never serve both roles.
	Falcon1024V1 = "aplane.witness-falcon1024.v1"

	Falcon1024PublicKeySize  = falconparams.PublicKeySize
	Falcon1024PrivateKeySize = falconparams.PrivateKeySize
	Falcon1024SignatureSize  = falconparams.CompressedSignatureMaxSize

	IDLength = 52
	idDomain = "APLANE_WITNESS_KEY_ID_V1"
)

var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// IsKeyType reports whether keyType is a supported witness-key type.
func IsKeyType(keyType string) bool {
	return keyType == Falcon1024V1
}

// PublicKeySize returns the public-key size for a supported witness-key type.
func PublicKeySize(keyType string) (int, bool) {
	switch keyType {
	case Falcon1024V1:
		return Falcon1024PublicKeySize, true
	default:
		return 0, false
	}
}

// PrivateKeySize returns the private-key size for a supported witness-key type.
func PrivateKeySize(keyType string) (int, bool) {
	switch keyType {
	case Falcon1024V1:
		return Falcon1024PrivateKeySize, true
	default:
		return 0, false
	}
}

// ID returns the canonical Witness Key ID for a supported key type and public
// key.
func ID(keyType string, publicKey []byte) (string, error) {
	wantSize, ok := PublicKeySize(keyType)
	if !ok {
		return "", fmt.Errorf("key type %q is not a witness key type", keyType)
	}
	if len(publicKey) != wantSize {
		return "", fmt.Errorf("witness public key length %d invalid (expected %d bytes)", len(publicKey), wantSize)
	}
	return DeriveID(keyType, publicKey), nil
}

// DeriveID computes the family-generic Witness Key ID without consulting the
// compiled key-type vocabulary. Callers own key-type and public-key validation.
func DeriveID(keyType string, publicKey []byte) string {
	var encoded []byte
	encoded = appendField(encoded, []byte(idDomain))
	encoded = appendField(encoded, []byte(keyType))
	encoded = appendField(encoded, publicKey)
	digest := sha512.Sum512_256(encoded)
	return idEncoding.EncodeToString(digest[:])
}

// NormalizeID validates and canonicalizes a Witness Key ID.
func NormalizeID(value string) (string, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", fmt.Errorf("witness key ID is required")
	}
	if len(raw) != IDLength {
		return "", fmt.Errorf("witness key ID length %d invalid (expected %d characters)", len(raw), IDLength)
	}
	decoded, err := idEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("witness key ID must be uppercase base32 without padding: %w", err)
	}
	if len(decoded) != sha512.Size256 {
		return "", fmt.Errorf("witness key ID digest length %d invalid (expected %d bytes)", len(decoded), sha512.Size256)
	}
	if idEncoding.EncodeToString(decoded) != raw {
		return "", fmt.Errorf("witness key ID must be canonical uppercase base32 without padding")
	}
	return raw, nil
}

// IsID reports whether value is a canonical Witness Key ID.
func IsID(value string) bool {
	_, err := NormalizeID(value)
	return err == nil
}

func appendField(dst, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	dst = append(dst, length[:]...)
	return append(dst, value...)
}
