// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package witness owns the role-neutral witness-key vocabulary and identity
// derivation. It is a leaf package so key classification is available without
// provider or algorithm-family registration.
package witness

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/falconparams"
)

const (
	// Falcon1024V1 is a non-spending Falcon-1024 witness key, held by a
	// cosigner.
	Falcon1024V1 = "aplane.witness-falcon1024.v1"

	Falcon1024PublicKeySize  = falconparams.PublicKeySize
	Falcon1024PrivateKeySize = falconparams.PrivateKeySize
	Falcon1024SignatureSize  = falconparams.CompressedSignatureMaxSize

	// Ed25519V1 is a non-spending Ed25519 witness key, held by a cosigner.
	// Its public key is also a valid Algorand address, but it signs only a
	// witness's domain-tagged message, never a transaction.
	Ed25519V1 = "aplane.witness-ed25519.v1"

	Ed25519PublicKeySize  = ed25519.PublicKeySize
	Ed25519PrivateKeySize = ed25519.PrivateKeySize
	Ed25519SignatureSize  = ed25519.SignatureSize

	IDLength = 52
	idDomain = "APLANE_WITNESS_KEY_ID_V1"
)

var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// KeyTypes lists the supported witness-key types in the order a picker offers
// them: the post-quantum one first.
var KeyTypes = []string{Falcon1024V1, Ed25519V1}

// IsKeyType reports whether keyType is a supported witness-key type.
func IsKeyType(keyType string) bool {
	return slices.Contains(KeyTypes, keyType)
}

// PublicKeySize returns the public-key size for a supported witness-key type.
func PublicKeySize(keyType string) (int, bool) {
	switch keyType {
	case Falcon1024V1:
		return Falcon1024PublicKeySize, true
	case Ed25519V1:
		return Ed25519PublicKeySize, true
	default:
		return 0, false
	}
}

// PrivateKeySize returns the private-key size for a supported witness-key type.
func PrivateKeySize(keyType string) (int, bool) {
	switch keyType {
	case Falcon1024V1:
		return Falcon1024PrivateKeySize, true
	case Ed25519V1:
		return Ed25519PrivateKeySize, true
	default:
		return 0, false
	}
}

// AlgorithmName names a witness-key type's signature algorithm for display.
func AlgorithmName(keyType string) (string, bool) {
	switch keyType {
	case Falcon1024V1:
		return "Falcon-1024", true
	case Ed25519V1:
		return "Ed25519", true
	default:
		return "", false
	}
}

// AccountAddress is the Algorand address a witness key's public key also is.
// Only an Ed25519 key's is one: hasAddress is false for any other type, and an
// Ed25519 key of the wrong length is an error.
func AccountAddress(keyType string, publicKey []byte) (address [32]byte, hasAddress bool, err error) {
	if keyType != Ed25519V1 {
		return address, false, nil
	}
	if len(publicKey) != Ed25519PublicKeySize {
		return address, true, fmt.Errorf("witness public key length %d invalid (expected %d bytes)", len(publicKey), Ed25519PublicKeySize)
	}
	copy(address[:], publicKey)
	return address, true, nil
}

// PostQuantum reports whether a supported witness-key type's signatures are
// meant to resist a quantum computer: Falcon-1024's are, Ed25519's are not.
func PostQuantum(keyType string) bool {
	return keyType == Falcon1024V1
}

// SignatureMaxSize returns the largest signature a supported witness-key type
// makes: Falcon-1024's compressed maximum, or Ed25519's fixed size.
func SignatureMaxSize(keyType string) (int, bool) {
	switch keyType {
	case Falcon1024V1:
		return Falcon1024SignatureSize, true
	case Ed25519V1:
		return Ed25519SignatureSize, true
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
