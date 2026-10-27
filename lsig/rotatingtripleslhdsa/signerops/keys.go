// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerops implements stage derivation and signing for the rotating SLH-DSA triple.
package signerops

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/crypto/slhdsa"
	"github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/stage"

	"github.com/algorand/falcon"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
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

// StageKeys owns one stage's private keys. Call Zero after use.
type StageKeys struct {
	slh     *slhdsa.SigningKey
	ed25519 ed25519.PrivateKey
	falcon  falcongo.KeyPair
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
	var edSeed [rotatinghybrid.Ed25519SeedSize]byte
	if err := d.ExpandStage(Ed25519InfoTag, i, edSeed[:]); err != nil {
		keys.Zero()
		return nil, stage.Program{}, err
	}
	keys.ed25519 = ed25519.NewKeyFromSeed(edSeed[:])
	crypto.ZeroBytes(edSeed[:])
	var falconSeed [rotatinghybrid.FalconSeedSize]byte
	if err := d.ExpandStage(FalconInfoTag, i, falconSeed[:]); err != nil {
		keys.Zero()
		return nil, stage.Program{}, err
	}
	keys.falcon, err = falcongo.GenerateKeyPair(falconSeed[:])
	crypto.ZeroBytes(falconSeed[:])
	if err != nil {
		keys.Zero()
		return nil, stage.Program{}, fmt.Errorf("generate stage %d Falcon key: %w", i, err)
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
	copy(pub.Ed25519[:], k.ed25519.Public().(ed25519.PublicKey))
	copy(pub.Falcon[:], k.falcon.PublicKey[:])
	return pub
}

// Sign signs the raw 32-byte transaction ID. SLH uses the FIPS 205 pure
// interface with an empty context and deterministic opt_rand = PK.seed,
// under stage.Params.
func (k *StageKeys) Sign(message []byte) (slhSig, edSig, falconSig []byte, err error) {
	if len(message) != 32 {
		return nil, nil, nil, errors.New("stage message must be a 32-byte TxID")
	}
	slhSig, err = stage.Params.Sign(k.slh, message, nil, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	falconSig, err = k.falcon.Sign(message)
	if err != nil {
		crypto.ZeroBytes(slhSig)
		return nil, nil, nil, err
	}
	return slhSig, ed25519.Sign(k.ed25519, message), falconSig, nil
}

// Zero overwrites every private key.
func (k *StageKeys) Zero() {
	if k == nil {
		return
	}
	if k.slh != nil {
		k.slh.Zero()
	}
	crypto.ZeroBytes(k.ed25519)
	crypto.ZeroBytes(k.falcon.PrivateKey[:])
}

// Verify checks the three signatures against the constants embedded in a
// stage program, as the AVM program will.
func Verify(keys *stage.PublicKeys, message, slhSig, ed25519Sig, falconSig []byte) error {
	if len(message) != 32 {
		return errors.New("stage message must be a 32-byte TxID")
	}
	if keys == nil {
		return errors.New("stage public keys are nil")
	}
	if !ed25519.Verify(keys.Ed25519[:], message, ed25519Sig) {
		return errors.New("stage Ed25519 signature is invalid")
	}
	if len(falconSig) > stage.FalconSignatureMaxSize {
		return fmt.Errorf("stage Falcon signature is %d bytes, maximum is %d", len(falconSig), stage.FalconSignatureMaxSize)
	}
	if err := falcongo.Verify(message, falcon.CompressedSignature(falconSig), falcon.PublicKey(keys.Falcon)); err != nil {
		return fmt.Errorf("stage Falcon signature: %w", err)
	}
	if err := stage.Params.Verify(&slhdsa.PublicKey{Seed: keys.Seed, Root: keys.Root}, message, slhSig, nil); err != nil {
		return fmt.Errorf("stage SLH-DSA signature: %w", err)
	}
	return nil
}
