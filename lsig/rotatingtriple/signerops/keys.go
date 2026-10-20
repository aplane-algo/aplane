// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerops holds the signer-side private-key operations of the
// aplane.rotating-triple-wots.v1 key type: stage key derivation and the
// WOTS, Ed25519 and Falcon-1024 signatures over a transaction ID.
//
// Every stage derives from the account seed under the key type's own HKDF
// label, so no stage key is shared with another rotating key type: the public
// account tag once, and per stage the 67 WOTS chain secrets, the Ed25519 seed
// and the Falcon-1024 seed. The stage tweak binds the WOTS chains to the
// network, the account and the stage number.
package signerops

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/crypto/wots"
	"github.com/aplane-algo/aplane/lsig/rotatingtriple/stage"

	"github.com/algorand/falcon"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

const (
	// DerivationLabel is the HKDF salt of this key type.
	DerivationLabel = "APLANE_ROTATING_TRIPLE_V1"

	// FalconInfoTag selects a stage's Falcon-1024 seed, Ed25519InfoTag its
	// Ed25519 seed, TagInfoTag the public account tag and WotsInfoTag a
	// stage's 67 WOTS chain secrets. The values match the other rotating key
	// types; the label keeps the derived keys apart.
	FalconInfoTag  byte = 0x01
	Ed25519InfoTag byte = 0x02
	TagInfoTag     byte = 0x10
	WotsInfoTag    byte = 0x11

	// AccountTagSize is the public account tag mixed into every tweak.
	AccountTagSize = 32
)

// NewDeriver binds a seed to a network under this key type's label.
func NewDeriver(seed *rotatinghybrid.Seed, genesisHash [rotatinghybrid.GenesisHashSize]byte) (*rotatinghybrid.Deriver, error) {
	return rotatinghybrid.NewDeriverWithLabel(seed, genesisHash, DerivationLabel)
}

// AccountTag derives the public account tag: HKDF(0x10 || G), 32 bytes.
func AccountTag(d *rotatinghybrid.Deriver) ([AccountTagSize]byte, error) {
	var tag [AccountTagSize]byte
	if err := d.ExpandAccount(TagInfoTag, tag[:]); err != nil {
		return tag, err
	}
	return tag, nil
}

// StageKeys are the private keys of one stage. Callers must Zero them.
type StageKeys struct {
	tweak   wots.Tweak
	wots    []byte
	wotsPub wots.PublicKey
	ed25519 ed25519.PrivateKey
	falcon  falcongo.KeyPair
}

// DeriveStage derives stage i's keys and program.
func DeriveStage(d *rotatinghybrid.Deriver, i uint64) (*StageKeys, stage.Program, error) {
	if d == nil {
		return nil, stage.Program{}, errors.New("rotating triple deriver is nil")
	}
	tag, err := AccountTag(d)
	if err != nil {
		return nil, stage.Program{}, err
	}
	keys := &StageKeys{
		tweak: wots.NewTweak(d.GenesisHash(), tag, i),
		wots:  make([]byte, wots.SecretKeySize),
	}
	if err := d.ExpandStage(WotsInfoTag, i, keys.wots); err != nil {
		keys.Zero()
		return nil, stage.Program{}, err
	}
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
	keys.wotsPub, err = wots.PublicKeyOf(&keys.tweak, keys.wots)
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
	pub := &stage.PublicKeys{Tweak: k.tweak, Wots: k.wotsPub}
	copy(pub.Ed25519[:], k.ed25519.Public().(ed25519.PublicKey))
	copy(pub.Falcon[:], k.falcon.PublicKey[:])
	return pub
}

// Sign returns the stage's argument 0 (WOTS), argument 1 (Ed25519) and
// argument 2 (Falcon-1024) signatures over message, which for a spend is the
// raw 32-byte transaction ID. A stage must sign one message only: a second
// spends its WOTS key.
func (k *StageKeys) Sign(message []byte) (wotsSig, ed25519Sig, falconSig []byte, err error) {
	wotsSig, err = wots.Sign(&k.tweak, k.wots, message)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign with stage WOTS key: %w", err)
	}
	falconSig, err = k.falcon.Sign(message)
	if err != nil {
		crypto.ZeroBytes(wotsSig)
		return nil, nil, nil, fmt.Errorf("sign with stage Falcon key: %w", err)
	}
	return wotsSig, ed25519.Sign(k.ed25519, message), falconSig, nil
}

// Zero overwrites every private key.
func (k *StageKeys) Zero() {
	if k == nil {
		return
	}
	crypto.ZeroBytes(k.wots)
	crypto.ZeroBytes(k.ed25519)
	crypto.ZeroBytes(k.falcon.PrivateKey[:])
}

// Verify checks the three signatures against the constants embedded in a
// stage program, as the AVM program will.
func Verify(keys *stage.PublicKeys, message, wotsSig, ed25519Sig, falconSig []byte) error {
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
	if err := wots.Verify(&keys.Tweak, keys.Wots, message, wotsSig); err != nil {
		return fmt.Errorf("stage WOTS signature: %w", err)
	}
	return nil
}
