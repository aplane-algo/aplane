// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers the triple hybrid rotating key type's
// signer-side hooks: the key file codec, the stage cryptography and the
// generator.
package signerreg

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/signerops"
	"github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/stage"
)

var registerOnce sync.Once

// Register installs the key file codec, the stage cryptography and the
// generator. It is safe to call more than once.
func Register() {
	registerOnce.Do(func() {
		keys.RegisterRotatingCodec(rotatingkey.RotatingTripleSlhdsaV1, keys.RotatingCodec{
			AccountAddress: accountAddress,
			ValidateSeed:   validateSeed,
		})
		signing.RegisterRotatingStageOps(rotatingkey.RotatingTripleSlhdsaV1, signerops.StageOps{})
		keygen.Register(generator{})
	})
}

// NewKeyPayload derives stage 0 from seed on the network named by
// genesisHash and returns the key file payload and the account address. The
// caller owns the payload and must zero it.
func NewKeyPayload(seed *rotatinghybrid.Seed, genesisHash [rotatinghybrid.GenesisHashSize]byte) (*keys.Payload, string, error) {
	d, err := signerops.NewDeriver(seed, genesisHash)
	if err != nil {
		return nil, "", err
	}
	defer d.Zero()
	stageKeys, program, err := signerops.DeriveStage(d, 0)
	if err != nil {
		return nil, "", err
	}
	defer stageKeys.Zero()
	payload := keys.NewRotatingLSigPayload(rotatingkey.RotatingTripleSlhdsaV1, seed[:], genesisHash[:], packPublicKeys(stageKeys.PublicKeys()))
	return payload, program.Address.String(), nil
}

// packedSize is the key file's stage 0 record size.
const packedSize = 2*stage.HashSize + stage.FalconPublicKeySize + stage.ConstantSize

// packPublicKeys encodes seed16 || root16 || Falcon1793 || Ed25519 32.
func packPublicKeys(pk *stage.PublicKeys) []byte {
	packed := make([]byte, 0, packedSize)
	packed = append(packed, pk.Seed[:]...)
	packed = append(packed, pk.Root[:]...)
	packed = append(packed, pk.Falcon[:]...)
	return append(packed, pk.Ed25519[:]...)
}

func unpackPublicKeys(packed []byte) (*stage.PublicKeys, error) {
	if len(packed) != packedSize {
		return nil, fmt.Errorf("stage public key length %d invalid", len(packed))
	}
	pk := &stage.PublicKeys{}
	rest := packed[copy(pk.Seed[:], packed):]
	rest = rest[copy(pk.Root[:], rest):]
	rest = rest[copy(pk.Falcon[:], rest):]
	copy(pk.Ed25519[:], rest)
	return pk, nil
}

func accountAddress(stageZeroPublicKey []byte) (string, error) {
	pk, err := unpackPublicKeys(stageZeroPublicKey)
	if err != nil {
		return "", err
	}
	program, err := stage.Build(pk)
	if err != nil {
		return "", err
	}
	return program.Address.String(), nil
}

func validateSeed(seedBytes, genesisHashBytes, stageZeroPublicKey []byte) error {
	var seed rotatinghybrid.Seed
	var genesisHash [rotatinghybrid.GenesisHashSize]byte
	if len(seedBytes) != len(seed) || len(genesisHashBytes) != len(genesisHash) {
		return fmt.Errorf("seed or genesis hash has the wrong length")
	}
	copy(seed[:], seedBytes)
	defer seed.Zero()
	copy(genesisHash[:], genesisHashBytes)
	d, err := signerops.NewDeriver(&seed, genesisHash)
	if err != nil {
		return err
	}
	defer d.Zero()
	stageKeys, _, err := signerops.DeriveStage(d, 0)
	if err != nil {
		return err
	}
	defer stageKeys.Zero()
	if !bytes.Equal(packPublicKeys(stageKeys.PublicKeys()), stageZeroPublicKey) {
		return fmt.Errorf("stage 0 public key mismatch")
	}
	return nil
}
