// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"crypto/sha256"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/stage"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// openTestMessage is the fixed 32-byte message CheckStageOpens signs: the
// hash of a label, not a transaction ID, so a signature over it cannot
// authorize anything. The open test runs only on a rotation target before
// it is live, and its signatures are never released.
var openTestMessage = func() []byte {
	sum := sha256.Sum256([]byte("APLANE_ROTATING_TRIPLE_SLHDSA_V1 stage open test"))
	return sum[:]
}()

// StageOps implements signing.RotatingStageOps for
// aplane.rotating-triple-slhdsa.v1.
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
// in its program. Test signatures are wiped before returning and never released.
func (StageOps) CheckStageOpens(key *signing.RotatingKeyMaterial, i uint64) error {
	sig, err := signAndVerify(key, i, openTestMessage)
	zeroArgs(sig.Args)
	return err
}

// SignStage signs message with stage i and returns the program with the
// SLH-DSA signature split as stage.ChunkSizes lists, then the Ed25519 and
// Falcon signatures, as its arguments. SLH-DSA is stateless, so the leaf
// index is ignored.
func (StageOps) SignStage(key *signing.RotatingKeyMaterial, i uint64, _ uint32, message []byte) (signing.RotatingStageSignature, error) {
	return signAndVerify(key, i, message)
}

func signAndVerify(key *signing.RotatingKeyMaterial, i uint64, message []byte) (signing.RotatingStageSignature, error) {
	keys, program, err := deriveFromMaterial(key, i)
	if err != nil {
		return signing.RotatingStageSignature{}, err
	}
	defer keys.Zero()
	slhSig, ed25519Sig, falconSig, err := keys.Sign(message)
	if err != nil {
		return signing.RotatingStageSignature{}, fmt.Errorf("sign with stage %d: %w", i, err)
	}
	args := make([][]byte, 0, len(stage.ChunkSizes)+2)
	off := 0
	for _, n := range stage.ChunkSizes {
		args = append(args, slhSig[off:off+n])
		off += n
	}
	args = append(args, ed25519Sig, falconSig)
	// On every error path the signatures are never handed to the caller, so
	// they are wiped here.
	embedded, _, err := stage.Parse(program.Bytecode)
	if err != nil {
		zeroArgs(args)
		return signing.RotatingStageSignature{}, fmt.Errorf("parse stage %d program: %w", i, err)
	}
	if err := Verify(embedded, message, slhSig, ed25519Sig, falconSig); err != nil {
		zeroArgs(args)
		return signing.RotatingStageSignature{}, fmt.Errorf("stage %d signature does not verify: %w", i, err)
	}
	return signing.RotatingStageSignature{Program: program.Bytecode, Args: args}, nil
}

// zeroArgs overwrites every argument buffer.
func zeroArgs(args [][]byte) {
	for _, a := range args {
		crypto.ZeroBytes(a)
	}
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
