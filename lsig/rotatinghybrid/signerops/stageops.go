// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatinghybrid/stage"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// openTestMessage is the fixed message CheckStageOpens signs. It is not a
// transaction ID, so a signature over it cannot authorize anything.
var openTestMessage = []byte("APLANE_ROTATING_HYBRID_V1 stage open test")

// StageOps implements signing.RotatingStageOps for aplane.rotating-hybrid.v1.
type StageOps struct{}

var _ signing.RotatingStageOps = StageOps{}

// StageAddress derives stage i and returns its program address.
func (StageOps) StageAddress(key *signing.RotatingKeyMaterial, i uint64) (types.Address, error) {
	keys, program, err := deriveFromMaterial(key, i)
	if err != nil {
		return types.Address{}, err
	}
	keys.Zero()
	return program.Address, nil
}

// CheckStageOpens proves stage i's derived keys match the keys embedded in
// its program.
func (StageOps) CheckStageOpens(key *signing.RotatingKeyMaterial, i uint64) error {
	_, err := signAndVerify(key, i, openTestMessage)
	return err
}

// SignStage signs message with stage i and returns the program with
// [falcon_sig, ed25519_sig] as its arguments.
func (StageOps) SignStage(key *signing.RotatingKeyMaterial, i uint64, message []byte) (signing.RotatingStageSignature, error) {
	return signAndVerify(key, i, message)
}

func signAndVerify(key *signing.RotatingKeyMaterial, i uint64, message []byte) (signing.RotatingStageSignature, error) {
	keys, program, err := deriveFromMaterial(key, i)
	if err != nil {
		return signing.RotatingStageSignature{}, err
	}
	defer keys.Zero()
	falconSig, ed25519Sig, err := keys.Sign(message)
	if err != nil {
		return signing.RotatingStageSignature{}, fmt.Errorf("sign with stage %d: %w", i, err)
	}
	// Verify against the keys parsed back out of the program bytes, not the
	// derived keys, so the check covers the bytes the network will run.
	embedded, _, err := stage.Parse(program.Bytecode)
	if err != nil {
		return signing.RotatingStageSignature{}, fmt.Errorf("parse stage %d program: %w", i, err)
	}
	if err := Verify(embedded, message, falconSig, ed25519Sig); err != nil {
		return signing.RotatingStageSignature{}, fmt.Errorf("stage %d signature does not verify: %w", i, err)
	}
	return signing.RotatingStageSignature{
		Program: program.Bytecode,
		Args:    [][]byte{falconSig, ed25519Sig},
	}, nil
}

func deriveFromMaterial(key *signing.RotatingKeyMaterial, i uint64) (*StageKeys, stage.Program, error) {
	if key == nil {
		return nil, stage.Program{}, fmt.Errorf("rotating key material is nil")
	}
	var seed rotatinghybrid.Seed
	var genesisHash [rotatinghybrid.GenesisHashSize]byte
	if len(key.Seed) != len(seed) || len(key.GenesisHash) != len(genesisHash) {
		return nil, stage.Program{}, fmt.Errorf("rotating key material has the wrong size")
	}
	copy(seed[:], key.Seed)
	defer seed.Zero()
	copy(genesisHash[:], key.GenesisHash)
	d, err := rotatinghybrid.NewDeriver(&seed, genesisHash)
	if err != nil {
		return nil, stage.Program{}, err
	}
	defer d.Zero()
	return DeriveStage(d, i)
}
