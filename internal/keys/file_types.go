// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"github.com/aplane-algo/aplane/internal/signingargs"
)

// ImportKeyResult contains the results of importing a key.
type ImportKeyResult struct {
	Address     string
	LsigFile    string
	PublicFile  string
	PrivateFile string
}

const (
	CategoryEd25519         = "ed25519"
	CategoryNativePQ        = "native_pq"
	CategoryDSALsig         = "dsa_lsig"
	CategoryGenericLsig     = "generic_lsig"
	CategoryWitness         = "witness"
	CurrentKeyFormatVersion = 1
)

const CurrentSigningMetadataVersion = 1

// BoundedSigningMetadataVersion adds the complete durable bounded signing
// contract. Version 1 remains valid only for non-bounded LogicSig keys.
const BoundedSigningMetadataVersion = 2

// StoredSigningArg records the signing-time LogicSig arg contract captured
// into a key file. Keys use this at signing time so installed template metadata
// cannot change the behavior or usability of an existing key.
type StoredSigningArg = signingargs.Info

// SaltCounterPtr returns a pointer to counter for DSA LogicSig key files, where
// zero is a valid persisted salt counter and must not be omitted.
func SaltCounterPtr(counter byte) *byte {
	return &counter
}
