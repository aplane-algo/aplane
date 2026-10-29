// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerops implements stage derivation and signing for the rotating SLH-DSA triple.
package signerops

import (
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/crypto/slhdsa"
	"github.com/aplane-algo/aplane/lsig/rotatingfamily/stagesign"
	"github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/stage"
)

const (
	DerivationLabel           = "APLANE_ROTATING_TRIPLE_SLHDSA_V1"
	FalconInfoTag        byte = 1
	Ed25519InfoTag       byte = 2
	SLHSeedInfoTag       byte = 3
	SLHPrfInfoTag        byte = 4
	SLHPublicSeedInfoTag byte = 5
)

// NewDeriver binds a seed to a network under this key type's label.
func NewDeriver(seed *rotatinghybrid.Seed, genesisHash [rotatinghybrid.GenesisHashSize]byte) (*rotatinghybrid.Deriver, error) {
	return rotatinghybrid.NewDeriverWithLabel(seed, genesisHash, DerivationLabel)
}

// signSLH signs with stage.Params' pure interface, an empty context and
// deterministic randomness; tests replace it to observe the signature buffer.
var signSLH = func(key *slhdsa.SigningKey, message []byte) ([]byte, error) {
	return stage.Params.Sign(key, message, nil, nil)
}

// StageKeys owns one stage's private keys. Call Zero after use.
type StageKeys struct {
	slh       *slhdsa.SigningKey
	classical *stagesign.ClassicalKeys
}

// DeriveStage derives stage i's keys and program.
func DeriveStage(d *rotatinghybrid.Deriver, i uint64) (*StageKeys, stage.Program, error) {
	if d == nil {
		return nil, stage.Program{}, errors.New("rotating triple deriver is nil")
	}
	keys := &StageKeys{}
	var secretSeed, prfSeed, publicSeed [slhdsa.N]byte
	defer crypto.ZeroBytes(secretSeed[:])
	defer crypto.ZeroBytes(prfSeed[:])
	if err := d.ExpandStage(SLHSeedInfoTag, i, secretSeed[:]); err != nil {
		return nil, stage.Program{}, err
	}
	if err := d.ExpandStage(SLHPrfInfoTag, i, prfSeed[:]); err != nil {
		return nil, stage.Program{}, err
	}
	if err := d.ExpandStage(SLHPublicSeedInfoTag, i, publicSeed[:]); err != nil {
		return nil, stage.Program{}, err
	}
	keys.slh = stage.Params.KeyGenFromSeeds(&secretSeed, &prfSeed, &publicSeed)
	var err error
	keys.classical, err = stagesign.DeriveClassicalKeys(d, i, Ed25519InfoTag, FalconInfoTag)
	if err != nil {
		keys.Zero()
		return nil, stage.Program{}, err
	}
	program, err := stage.Build(keys.PublicKeys())
	if err != nil {
		keys.Zero()
		return nil, stage.Program{}, fmt.Errorf("build stage %d program: %w", i, err)
	}
	return keys, program, nil
}

// PublicKeys returns the constants a stage program embeds.
func (k *StageKeys) PublicKeys() *stage.PublicKeys {
	pub := &stage.PublicKeys{Seed: k.slh.Public.Seed, Root: k.slh.Public.Root}
	pub.Ed25519, pub.Falcon = k.classical.PublicKeys()
	return pub
}

// Sign signs the raw 32-byte transaction ID. SLH uses the FIPS 205 pure
// interface with an empty context and deterministic opt_rand = PK.seed,
// under stage.Params. If the Ed25519 or Falcon-1024 signing fails, the SLH-DSA
// signature is wiped before the error returns.
func (k *StageKeys) Sign(message []byte) (slhSig, edSig, falconSig []byte, err error) {
	if err := stagesign.CheckMessage(message); err != nil {
		return nil, nil, nil, err
	}
	slhSig, err = signSLH(k.slh, message)
	if err != nil {
		return nil, nil, nil, err
	}
	edSig, falconSig, err = k.classical.Sign(message)
	if err != nil {
		crypto.ZeroBytes(slhSig)
		return nil, nil, nil, err
	}
	return slhSig, edSig, falconSig, nil
}

// Zero overwrites every private key.
func (k *StageKeys) Zero() {
	if k == nil {
		return
	}
	if k.slh != nil {
		k.slh.Zero()
	}
	k.classical.Zero()
}

// Verify checks the three signatures against the constants embedded in a
// stage program, as the AVM program will.
func Verify(keys *stage.PublicKeys, message, slhSig, ed25519Sig, falconSig []byte) error {
	if keys == nil {
		return errors.New("stage public keys are nil")
	}
	if err := stagesign.VerifyClassical(&keys.Ed25519, &keys.Falcon, message, ed25519Sig, falconSig); err != nil {
		return err
	}
	if err := stage.Params.Verify(&slhdsa.PublicKey{Seed: keys.Seed, Root: keys.Root}, message, slhSig, nil); err != nil {
		return fmt.Errorf("stage SLH-DSA signature: %w", err)
	}
	return nil
}
