// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keytypes holds the cosigner vocabulary cosigned accounts share. Bare
// witness key vocabulary and identity derivation live in internal/witness.
package keytypes

const (
	// ParameterCosignerPublicKey is the durable creation parameter that records
	// the cosigner witness public key embedded in a cosigned account's LogicSig.
	ParameterCosignerPublicKey = "cosigner_public_key"
)
