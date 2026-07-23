// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keytypes owns key types for guarded sentry accounts. Bare witness
// key vocabulary and identity derivation live in internal/witness.
package keytypes

import "github.com/aplane-algo/aplane/internal/witness"

const (
	// GuardedFalcon1024Sentry1024V1 is the user-account key type whose
	// LogicSig verifies a Falcon-1024 user signature plus a Falcon-1024
	// sentry witness signature.
	GuardedFalcon1024Sentry1024V1 = "aplane.falcon1024-sentry1024.v1"

	// ParameterSentryPublicKey is the durable creation parameter that records
	// the sentry witness public key embedded in a sentry-backed LogicSig.
	ParameterSentryPublicKey = "sentry_public_key"
)

// IsGuardedAccountKeyType reports whether keyType names a guarded spending
// account that requires the component signing and assembly flow.
func IsGuardedAccountKeyType(keyType string) bool {
	switch keyType {
	case GuardedFalcon1024Sentry1024V1:
		return true
	default:
		return false
	}
}

// IsSentryKeyType reports whether keyType is reserved by the sentry guarded-
// signing feature, either as a guarded account or a sentry-custodied witness.
func IsSentryKeyType(keyType string) bool {
	return witness.IsKeyType(keyType) || IsGuardedAccountKeyType(keyType)
}

// SentryComponentKeyTypeForGuardedAccount returns the witness key type used
// for the sentry component of a guarded account key type.
func SentryComponentKeyTypeForGuardedAccount(keyType string) (string, bool) {
	switch keyType {
	case GuardedFalcon1024Sentry1024V1:
		return witness.Falcon1024V1, true
	default:
		return "", false
	}
}
