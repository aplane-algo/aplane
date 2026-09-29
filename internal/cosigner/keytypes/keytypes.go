// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keytypes owns key types for guarded cosigner accounts. Bare witness
// key vocabulary and identity derivation live in internal/witness.
package keytypes

import "github.com/aplane-algo/aplane/internal/witness"

const (
	// GuardedFalcon1024Cosigner1024V1 is the user-account key type whose
	// LogicSig verifies a Falcon-1024 user signature plus a Falcon-1024
	// cosigner witness signature.
	GuardedFalcon1024Cosigner1024V1 = "aplane.falcon1024-cosigner1024.v1"

	// ParameterCosignerPublicKey is the durable creation parameter that records
	// the cosigner witness public key embedded in a cosigner-backed LogicSig.
	ParameterCosignerPublicKey = "cosigner_public_key"
)

// IsGuardedAccountKeyType reports whether keyType names a guarded spending
// account that requires the component signing and assembly flow.
func IsGuardedAccountKeyType(keyType string) bool {
	switch keyType {
	case GuardedFalcon1024Cosigner1024V1:
		return true
	default:
		return false
	}
}

// IsCosignerKeyType reports whether keyType is reserved by the cosigner guarded-
// signing feature, either as a guarded account or a cosigner-custodied witness.
func IsCosignerKeyType(keyType string) bool {
	return witness.IsKeyType(keyType) || IsGuardedAccountKeyType(keyType)
}

// CosignerComponentKeyTypeForGuardedAccount returns the witness key type used
// for the cosigner component of a guarded account key type.
func CosignerComponentKeyTypeForGuardedAccount(keyType string) (string, bool) {
	switch keyType {
	case GuardedFalcon1024Cosigner1024V1:
		return witness.Falcon1024V1, true
	default:
		return "", false
	}
}
