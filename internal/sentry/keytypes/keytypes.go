// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keytypes defines the sentry key-type vocabulary and pure Sentry Key
// ID construction.
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
	// SentryComponentEd25519V1 is a raw Ed25519 component-signing key. It is
	// not an Algorand spending account and must not be accepted by /sign.
	SentryComponentEd25519V1 = "aplane.sentry-ed25519.v1"

	// SentryComponentFalcon1024V1 is a raw Falcon-1024 component-signing key.
	// It is not an Algorand spending account and must not be accepted by /sign.
	SentryComponentFalcon1024V1 = "aplane.sentry-falcon1024.v1"

	// GuardedFalcon1024SentryEd25519V1 is the user-account key type whose LogicSig
	// verifies a Falcon-1024 user signature plus an Ed25519 sentry component
	// signature.
	GuardedFalcon1024SentryEd25519V1 = "aplane.falcon1024-sentry-ed25519.v1"

	// GuardedFalcon1024SentryFalcon1024V1 is the user-account key type whose
	// LogicSig verifies a Falcon-1024 user signature plus a Falcon-1024
	// sentry component signature.
	GuardedFalcon1024SentryFalcon1024V1 = "aplane.falcon1024-sentry-falcon1024.v1"

	// ParameterSentryPublicKey is the durable creation parameter that records
	// the sentry public key embedded in a guarded account LogicSig.
	ParameterSentryPublicKey = "sentry_public_key"

	// ComponentKeySelectorLength is the length of a canonical Sentry Key ID. It
	// matches the visual shape of Algorand
	// transaction IDs, but it is shorter than an Algorand address and must not
	// be treated as one.
	ComponentKeySelectorLength = 52

	componentKeySelectorDomain = "APLANE_COMPONENT_KEY_V1"
)

var componentKeySelectorEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// IsSentryComponentKeyType reports whether keyType names a sentry key
// that may only be used through /sign/component.
func IsSentryComponentKeyType(keyType string) bool {
	switch keyType {
	case SentryComponentEd25519V1, SentryComponentFalcon1024V1:
		return true
	default:
		return false
	}
}

// IsGuardedAccountKeyType reports whether keyType names a guarded spending
// account that requires the component signing and assembly flow.
func IsGuardedAccountKeyType(keyType string) bool {
	switch keyType {
	case GuardedFalcon1024SentryEd25519V1, GuardedFalcon1024SentryFalcon1024V1:
		return true
	default:
		return false
	}
}

// IsSentryKeyType reports whether keyType is any key type reserved by the
// sentry guarded-signing feature.
func IsSentryKeyType(keyType string) bool {
	return IsSentryComponentKeyType(keyType) || IsGuardedAccountKeyType(keyType)
}

// SentryComponentKeyTypeForGuardedAccount returns the sentry component
// key type embedded by a guarded account key type.
func SentryComponentKeyTypeForGuardedAccount(keyType string) (string, bool) {
	switch keyType {
	case GuardedFalcon1024SentryEd25519V1:
		return SentryComponentEd25519V1, true
	case GuardedFalcon1024SentryFalcon1024V1:
		return SentryComponentFalcon1024V1, true
	default:
		return "", false
	}
}

// ComponentKeySelector returns the canonical Sentry Key ID for a sentry key.
// Sentry Key IDs are uppercase base32-no-padding SHA-512/256 digests over a
// domain-separated key-type/public-key tuple, independent of the sentry key
// family.
func ComponentKeySelector(keyType string, publicKey []byte) (string, error) {
	if !IsSentryComponentKeyType(keyType) {
		return "", fmt.Errorf("key type %q is not a sentry key type", keyType)
	}
	wantSize, ok := ComponentPublicKeySize(keyType)
	if !ok {
		return "", fmt.Errorf("key type %q is not a sentry key type", keyType)
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

// NormalizeComponentKeySelector validates and canonicalizes a Sentry Key ID.
// IDs must already be canonical 52-character uppercase base32
// values with no padding.
func NormalizeComponentKeySelector(selector string) (string, error) {
	raw := strings.TrimSpace(selector)
	if raw == "" {
		return "", fmt.Errorf("sentry key ID is required")
	}
	if len(raw) != ComponentKeySelectorLength {
		return "", fmt.Errorf("sentry key ID length %d invalid (expected %d characters)", len(raw), ComponentKeySelectorLength)
	}
	decoded, err := componentKeySelectorEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("sentry key ID must be uppercase base32 without padding: %w", err)
	}
	if len(decoded) != sha512.Size256 {
		return "", fmt.Errorf("sentry key ID digest length %d invalid (expected %d bytes)", len(decoded), sha512.Size256)
	}
	if componentKeySelectorEncoding.EncodeToString(decoded) != raw {
		return "", fmt.Errorf("sentry key ID must be canonical uppercase base32 without padding")
	}
	return raw, nil
}

// IsComponentKeySelector reports whether selector is a syntactically valid
// Sentry Key ID.
func IsComponentKeySelector(selector string) bool {
	_, err := NormalizeComponentKeySelector(selector)
	return err == nil
}

// ComponentPublicKeySize returns the public key byte size for a sentry key
// type.
func ComponentPublicKeySize(keyType string) (int, bool) {
	switch keyType {
	case SentryComponentEd25519V1:
		return ed25519.PublicKeySize, true
	case SentryComponentFalcon1024V1:
		return falconfamily.PublicKeySize, true
	default:
		return 0, false
	}
}

// ComponentPrivateKeySize returns the private key byte size for a sentry key
// type.
func ComponentPrivateKeySize(keyType string) (int, bool) {
	switch keyType {
	case SentryComponentEd25519V1:
		return ed25519.PrivateKeySize, true
	case SentryComponentFalcon1024V1:
		return falconfamily.PrivateKeySize, true
	default:
		return 0, false
	}
}
