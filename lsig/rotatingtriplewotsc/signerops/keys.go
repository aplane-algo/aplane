// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerops implements stage derivation and signing for the rotating
// WOTS+C triple.
package signerops

import (
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/crypto/wotsc"
	"github.com/aplane-algo/aplane/lsig/rotatingfamily/stagesign"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/stage"
)

const (
	// DerivationLabel is the HKDF salt of this key type.
	DerivationLabel = "APLANE_ROTATING_TRIPLE_WOTSC_V1"

	// FalconInfoTag selects a stage's Falcon-1024 seed and Ed25519InfoTag its
	// Ed25519 seed; the values match the other rotating key types and the
	// label keeps the keys apart. SecretSeedInfoTag, PrfInfoTag and
	// PublicSeedInfoTag select a stage's WOTS+C secret seed, randomizer key
	// and public seed.
	FalconInfoTag     byte = 1
	Ed25519InfoTag    byte = 2
	SecretSeedInfoTag byte = 3
	PrfInfoTag        byte = 4
	PublicSeedInfoTag byte = 5
)

// NewDeriver binds a seed to a network under this key type's label.
func NewDeriver(seed *rotatinghybrid.Seed, genesisHash [rotatinghybrid.GenesisHashSize]byte) (*rotatinghybrid.Deriver, error) {
	return rotatinghybrid.NewDeriverWithLabel(seed, genesisHash, DerivationLabel)
}

// signHash makes the WOTS+C signature; tests replace it to observe the buffer.
var signHash = func(key *wotsc.SigningKey, leaf uint32, message []byte) ([]byte, error) {
	return key.Sign(leaf, message)
}

// StageKeys owns one stage's private keys. Call Zero after use.
type StageKeys struct {
	hash      *wotsc.SigningKey
	classical *stagesign.ClassicalKeys
}

// DeriveStage derives stage i's keys and program.
func DeriveStage(d *rotatinghybrid.Deriver, i uint64) (*StageKeys, stage.Program, error) {
	if d == nil {
		return nil, stage.Program{}, errors.New("rotating wotsc deriver is nil")
	}
	keys := &StageKeys{}
	var secretSeed, prfSeed, publicSeed [wotsc.N]byte
	defer crypto.ZeroBytes(secretSeed[:])
	defer crypto.ZeroBytes(prfSeed[:])
	if err := d.ExpandStage(SecretSeedInfoTag, i, secretSeed[:]); err != nil {
		return nil, stage.Program{}, err
	}
	if err := d.ExpandStage(PrfInfoTag, i, prfSeed[:]); err != nil {
		return nil, stage.Program{}, err
	}
	if err := d.ExpandStage(PublicSeedInfoTag, i, publicSeed[:]); err != nil {
		return nil, stage.Program{}, err
	}
	keys.hash = wotsc.NewSigningKey(&secretSeed, &prfSeed, &publicSeed)
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
	pub := &stage.PublicKeys{Seed: k.hash.Public.Seed, Root: k.hash.Public.Root}
	pub.Ed25519, pub.Falcon = k.classical.PublicKeys()
	return pub
}

// Sign signs the raw 32-byte transaction ID with the given WOTS+C leaf. The
// caller chooses the leaf and owns the one-time rule. If the Ed25519 or
// Falcon-1024 signing fails, the WOTS+C signature is wiped before the error
// returns.
func (k *StageKeys) Sign(leaf uint32, message []byte) (hashSig, edSig, falconSig []byte, err error) {
	if err := stagesign.CheckMessage(message); err != nil {
		return nil, nil, nil, err
	}
	hashSig, err = signHash(k.hash, leaf, message)
	if err != nil {
		return nil, nil, nil, err
	}
	edSig, falconSig, err = k.classical.Sign(message)
	if err != nil {
		crypto.ZeroBytes(hashSig)
		return nil, nil, nil, err
	}
	return hashSig, edSig, falconSig, nil
}

// Zero overwrites every private key.
func (k *StageKeys) Zero() {
	if k == nil {
		return
	}
	if k.hash != nil {
		k.hash.Zero()
	}
	k.classical.Zero()
}

// Verify checks the three signatures against the constants embedded in a
// stage program, as the AVM program will.
func Verify(keys *stage.PublicKeys, message, hashSig, ed25519Sig, falconSig []byte) error {
	if keys == nil {
		return errors.New("stage public keys are nil")
	}
	if err := stagesign.VerifyClassical(&keys.Ed25519, &keys.Falcon, message, ed25519Sig, falconSig); err != nil {
		return err
	}
	if err := wotsc.Verify(&wotsc.PublicKey{Seed: keys.Seed, Root: keys.Root}, message, hashSig); err != nil {
		return fmt.Errorf("stage WOTS+C signature: %w", err)
	}
	return nil
}
