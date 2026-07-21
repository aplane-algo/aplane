// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keytypes defines the sentry key-type vocabulary and pure Sentry Key
// ID construction.
//
// This package owns the CLASSIFY axis of key-type resolution (see
// docs/ARCH_KEYTYPE_AXES.md): it answers category questions about a key type
// (is it a guarded account? a sentry component? what key size?) from the key-type
// string alone. It therefore imports no registry, provider, or algorithm-family
// package — only the standard library — so classification is identical in every
// binary and works with no provider registered (the client config, keystore, and
// cache all rely on this). Keep it that way; do not route classification through
// the provider registry.
package keytypes

import (
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"strings"
)

// Falcon-1024 key sizes are fixed by the algorithm specification and define
// the sentry wire format; they can never change for the v1 key types. They
// are declared here as literals so this vocabulary package stays free of
// algorithm-family imports (keytypes_consistency_test.go cross-checks them
// against lsig/falcon1024/family).
const (
	// Falcon1024PublicKeySize is the frozen public-key size for Falcon sentry
	// component key types and their wire fixtures.
	Falcon1024PublicKeySize = 1793

	falcon1024PrivateKeySize = 2305
)

const (
	// SentryComponentFalcon1024V1 is a raw Falcon-1024 component-signing key.
	// It is not an Algorand spending account and must not be accepted by /sign.
	SentryComponentFalcon1024V1 = "aplane.sentry-falcon1024.v1"

	// GuardedFalcon1024Sentry1024V1 is the user-account key type whose
	// LogicSig verifies a Falcon-1024 user signature plus a Falcon-1024
	// sentry component signature.
	GuardedFalcon1024Sentry1024V1 = "aplane.falcon1024-sentry1024.v1"

	// CorridorV1 is a Falcon-1024 user-account key type whose LogicSig verifies
	// a Falcon-1024 user signature plus a Falcon-1024 sentry component
	// signature, then enforces a recipient corridor or sentry-authorized rekey.
	CorridorV1 = "aplane.corridor.v1"

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
	case SentryComponentFalcon1024V1:
		return true
	default:
		return false
	}
}

// IsGuardedAccountKeyType reports whether keyType names a guarded spending
// account that requires the component signing and assembly flow.
func IsGuardedAccountKeyType(keyType string) bool {
	switch keyType {
	case GuardedFalcon1024Sentry1024V1, CorridorV1:
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
	case GuardedFalcon1024Sentry1024V1, CorridorV1:
		return SentryComponentFalcon1024V1, true
	default:
		return "", false
	}
}

// ComponentKeySelector returns the canonical Sentry Key ID for a sentry key.
// Sentry Key IDs are uppercase base32-no-padding SHA-512/256 digests over a
// domain-separated key-type/public-key tuple, independent of the sentry key
// family. It gates on the compiled component key-type vocabulary and is the
// signer-side entry point; clients deriving selectors from runtime metadata
// use DeriveComponentKeySelector.
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
	return DeriveComponentKeySelector(keyType, publicKey), nil
}

// DeriveComponentKeySelector computes the canonical Sentry Key ID hash for
// any component key-type string and public key, without consulting the
// compiled key-type vocabulary. The derivation is family-generic by design
// (domain-separated SHA-512/256 over the key-type/public-key tuple), so
// clients can derive and cross-check selectors for component key types they
// learned from signer inventory at runtime. Callers own any public-key
// validation; end-to-end integrity comes from selector matching against the
// advertising endpoint and, ultimately, the on-chain LogicSig.
func DeriveComponentKeySelector(keyType string, publicKey []byte) string {
	h := sha512.New512_256()
	_, _ = h.Write([]byte(componentKeySelectorDomain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(keyType))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(publicKey)
	return componentKeySelectorEncoding.EncodeToString(h.Sum(nil))
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
	case SentryComponentFalcon1024V1:
		return Falcon1024PublicKeySize, true
	default:
		return 0, false
	}
}

// ComponentPrivateKeySize returns the private key byte size for a sentry key
// type.
func ComponentPrivateKeySize(keyType string) (int, bool) {
	switch keyType {
	case SentryComponentFalcon1024V1:
		return falcon1024PrivateKeySize, true
	default:
		return 0, false
	}
}
