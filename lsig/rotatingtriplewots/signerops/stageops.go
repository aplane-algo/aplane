// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingfamily/stagesign"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewots/stage"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// openTestMessage is the fixed 32-byte message CheckStageOpens signs
// (stagesign.OpenTestMessage). The open test runs only on a rotation target
// before it is live, so its WOTS signature is never released beside one over
// a spend from the same stage.
var openTestMessage = stagesign.OpenTestMessage(DerivationLabel)

// StageOps implements signing.RotatingStageOps for
// aplane.rotating-triple-wots.v1.
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
// in its program. The test signatures are wiped before returning: a WOTS
// signature carries chain secrets (an element whose digit is 0 is the chain's
// private seed itself), and this one is never released, so it must not
// outlive the keys it came from.
func (StageOps) CheckStageOpens(key *signing.RotatingKeyMaterial, i uint64) error {
	sig, err := signAndVerify(key, i, openTestMessage)
	stagesign.ZeroArgs(sig.Args)
	return err
}

// SignStage signs message with stage i and returns the program with
// [wots_sig, ed25519_sig, falcon_sig] as its arguments. A triple stage has
// one WOTS key, so the leaf index is ignored. A message that is not a 32-byte
// transaction ID is refused before any key is derived.
func (StageOps) SignStage(key *signing.RotatingKeyMaterial, i uint64, _ uint32, message []byte) (signing.RotatingStageSignature, error) {
	if err := stagesign.CheckMessage(message); err != nil {
		return signing.RotatingStageSignature{}, err
	}
	return signAndVerify(key, i, message)
}

func signAndVerify(key *signing.RotatingKeyMaterial, i uint64, message []byte) (signing.RotatingStageSignature, error) {
	keys, program, err := deriveFromMaterial(key, i)
	if err != nil {
		return signing.RotatingStageSignature{}, err
	}
	defer keys.Zero()
	wotsSig, ed25519Sig, falconSig, err := keys.Sign(message)
	if err != nil {
		return signing.RotatingStageSignature{}, fmt.Errorf("sign with stage %d: %w", i, err)
	}
	args := [][]byte{wotsSig, ed25519Sig, falconSig}
	// On every error path the signatures are never handed to the caller, so
	// they are wiped here; the WOTS signature carries chain secrets.
	embedded, _, err := stage.Parse(program.Bytecode)
	if err != nil {
		stagesign.ZeroArgs(args)
		return signing.RotatingStageSignature{}, fmt.Errorf("parse stage %d program: %w", i, err)
	}
	if err := Verify(embedded, message, wotsSig, ed25519Sig, falconSig); err != nil {
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
