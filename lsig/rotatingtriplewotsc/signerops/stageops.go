// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingfamily/stagesign"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/stage"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// openTestMessage is the fixed 32-byte message CheckStageOpens signs with a
// target stage's Ed25519 and Falcon keys (stagesign.OpenTestMessage). The
// WOTS+C half of the check is a constant comparison; no leaf is signed with.
var openTestMessage = stagesign.OpenTestMessage(DerivationLabel)

// StageOps implements signing.RotatingStageOps for
// aplane.rotating-triple-wotsc.v1. It has no state: each stage is its own tree,
// rebuilt from the key material per call in about 5 ms, and every secret is
// zeroed before returning.
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
// in its program: it test-signs with the stage's Ed25519 and Falcon keys and
// verifies against the program, and checks the program's root and seed against
// the rebuilt tree. It never signs with a WOTS+C leaf, because a leaf is
// one-time and the check runs on a stage that hasn't spent yet.
func (StageOps) CheckStageOpens(key *signing.RotatingKeyMaterial, i uint64) error {
	keys, program, err := deriveFromMaterial(key, i)
	if err != nil {
		return err
	}
	defer keys.Zero()
	embedded, _, err := stage.Parse(program.Bytecode)
	if err != nil {
		return fmt.Errorf("parse stage %d program: %w", i, err)
	}
	if embedded.Root != keys.hash.Public.Root || embedded.Seed != keys.hash.Public.Seed {
		return fmt.Errorf("stage %d program does not embed its tree", i)
	}
	edSig, falconSig, err := keys.classical.Sign(openTestMessage)
	if err != nil {
		return fmt.Errorf("stage %d open test: %w", i, err)
	}
	defer crypto.ZeroBytes(falconSig)
	if err := stagesign.VerifyClassical(&embedded.Ed25519, &embedded.Falcon, openTestMessage, edSig, falconSig); err != nil {
		return fmt.Errorf("stage %d open test: %w", i, err)
	}
	return nil
}

// SignStage signs message with leaf index of stage i and returns the program
// with [wotsc_sig, ed25519_sig, falcon_sig] as its arguments. The caller chooses
// the leaf and records its use. A message that is not a 32-byte transaction ID
// is refused before any key is derived.
func (StageOps) SignStage(key *signing.RotatingKeyMaterial, i uint64, index uint32, message []byte) (signing.RotatingStageSignature, error) {
	if err := stagesign.CheckMessage(message); err != nil {
		return signing.RotatingStageSignature{}, err
	}
	keys, program, err := deriveFromMaterial(key, i)
	if err != nil {
		return signing.RotatingStageSignature{}, err
	}
	defer keys.Zero()
	hashSig, edSig, falconSig, err := keys.Sign(index, message)
	if err != nil {
		return signing.RotatingStageSignature{}, fmt.Errorf("sign with stage %d: %w", i, err)
	}
	args := [][]byte{hashSig, edSig, falconSig}
	// On every error path the signatures are never handed to the caller, so
	// they are wiped here; a WOTS+C signature can carry a chain's secret start.
	embedded, _, err := stage.Parse(program.Bytecode)
	if err != nil {
		stagesign.ZeroArgs(args)
		return signing.RotatingStageSignature{}, fmt.Errorf("parse stage %d program: %w", i, err)
	}
	if err := Verify(embedded, message, hashSig, edSig, falconSig); err != nil {
		stagesign.ZeroArgs(args)
		return signing.RotatingStageSignature{}, fmt.Errorf("stage %d signature does not verify: %w", i, err)
	}
	return signing.RotatingStageSignature{Program: program.Bytecode, Args: args}, nil
}

func deriveFromMaterial(key *signing.RotatingKeyMaterial, i uint64) (*StageKeys, stage.Program, error) {
	if key == nil {
		return nil, stage.Program{}, fmt.Errorf("rotating key material is nil")
	}
	d, err := rotatinghybrid.OpenDeriver(key.Seed, key.GenesisHash, DerivationLabel)
	if err != nil {
		return nil, stage.Program{}, err
	}
	defer d.Zero()
	return DeriveStage(d, i)
}
