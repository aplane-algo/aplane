// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg holds the signer-side registration the rotating key
// types share: a descriptor of one key type's hooks, the call that installs
// them, and the generator. Each key type's own signerreg supplies its
// descriptor and calls Register under its own sync.Once, as the DSA families
// do around dsafamilyreg.RegisterSigner.
package signerreg

import (
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/signing"
)

// Descriptor is what one rotating key type registers.
type Descriptor struct {
	// KeyType is the versioned key type and Family its versionless routing
	// family.
	KeyType string
	Family  string

	// NewKeyPayload derives stage 0 from seed on the network named by
	// genesisHash and returns the key file payload and the account address.
	// The caller owns the payload and must zero it.
	NewKeyPayload func(seed *rotatinghybrid.Seed, genesisHash [rotatinghybrid.GenesisHashSize]byte) (*keys.Payload, string, error)

	// AccountAddress and ValidateSeed are the key file codec
	// (keys.RotatingCodec).
	AccountAddress func(stageZeroPublicKey []byte) (string, error)
	ValidateSeed   func(seed, genesisHash, stageZeroPublicKey []byte) error

	// StageOps is the key type's stage cryptography. It is registered as
	// given, never copied or wrapped, so a stateful implementation stays one
	// instance and optional capabilities such as signing.RotatingTreeOps
	// stay visible to the signing flow.
	StageOps signing.RotatingStageOps
}

// Register installs the key file codec, the stage cryptography and the
// generator. It keeps no bookkeeping of its own: the registries refuse a key
// type or family registered twice, so each key type calls it once.
func Register(d Descriptor) {
	if d.Family == "" || d.NewKeyPayload == nil {
		panic("rotating key type registration requires a family and a payload builder: " + d.KeyType)
	}
	keys.RegisterRotatingCodec(d.KeyType, keys.RotatingCodec{
		AccountAddress: d.AccountAddress,
		ValidateSeed:   d.ValidateSeed,
	})
	signing.RegisterRotatingStageOps(d.KeyType, d.StageOps)
	keygen.Register(generator{keyType: d.KeyType, family: d.Family, newKeyPayload: d.NewKeyPayload})
}
