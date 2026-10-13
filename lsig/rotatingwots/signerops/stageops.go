// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"crypto/sha256"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingwots/stage"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// openTestMessage is the fixed 32-byte message CheckStageOpens signs: the
// hash of a label, not a transaction ID, so a signature over it cannot
// authorize anything. The open test runs only on a rotation target before
// it is live, so its WOTS signature is never released beside one over a
// spend from the same stage.
var openTestMessage = func() []byte {
	sum := sha256.Sum256([]byte("APLANE_ROTATING_WOTS_V1 stage open test"))
	return sum[:]
}()

// StageOps implements signing.RotatingStageOps for
// aplane.rotating-wots-hybrid.v1.
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

// CheckStageOpens proves stage i's derived keys match the constants embedded
// in its program.
func (StageOps) CheckStageOpens(key *signing.RotatingKeyMaterial, i uint64) error {
	_, err := signAndVerify(key, i, openTestMessage)
	return err
}

// SignStage signs message with stage i and returns the program with
// [wots_sig, ed25519_sig] as its arguments.
func (StageOps) SignStage(key *signing.RotatingKeyMaterial, i uint64, message []byte) (signing.RotatingStageSignature, error) {
	return signAndVerify(key, i, message)
}

func signAndVerify(key *signing.RotatingKeyMaterial, i uint64, message []byte) (signing.RotatingStageSignature, error) {
	keys, program, err := deriveFromMaterial(key, i)
	if err != nil {
		return signing.RotatingStageSignature{}, err
	}
	defer keys.Zero()
	wotsSig, ed25519Sig, err := keys.Sign(message)
	if err != nil {
		return signing.RotatingStageSignature{}, fmt.Errorf("sign with stage %d: %w", i, err)
	}
	embedded, _, err := stage.Parse(program.Bytecode)
	if err != nil {
		return signing.RotatingStageSignature{}, fmt.Errorf("parse stage %d program: %w", i, err)
	}
	if err := Verify(embedded, message, wotsSig, ed25519Sig); err != nil {
		return signing.RotatingStageSignature{}, fmt.Errorf("stage %d signature does not verify: %w", i, err)
	}
	return signing.RotatingStageSignature{
		Program: program.Bytecode,
		Args:    [][]byte{wotsSig, ed25519Sig},
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
	d, err := NewDeriver(&seed, genesisHash)
	if err != nil {
		return nil, stage.Program{}, err
	}
	defer d.Zero()
	return DeriveStage(d, i)
}
