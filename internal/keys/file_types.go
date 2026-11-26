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
	CategoryRotatingLsig    = "rotating_lsig"
	CurrentKeyFormatVersion = 1
)

// CurrentSigningMetadataVersion is the signing-metadata version of every
// LogicSig key. A host account's key adds the host object beside it.
const CurrentSigningMetadataVersion = 1

// StoredSigningArg records the signing-time LogicSig arg contract captured
// into a key file. Keys use this at signing time so installed template metadata
// cannot change the behavior or usability of an existing key.
type StoredSigningArg = signingargs.Info
