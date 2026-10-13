// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerops holds the signer-side private-key operations of the
// aplane.rotating-wots-hybrid.v1 key type: stage key derivation and the
// paired WOTS and Ed25519 signatures over a transaction ID.
//
// Every stage derives from the account seed under the key type's own HKDF
// label: the public account tag once, and per stage the 67 WOTS chain
// secrets and the Ed25519 seed. The stage tweak binds the chains to the
// network, the account and the stage number.
package signerops

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/crypto/wots"
	"github.com/aplane-algo/aplane/lsig/rotatingwots/stage"
)

const (
	// DerivationLabel is the HKDF salt of this key type.
	DerivationLabel = "APLANE_ROTATING_WOTS_V1"

	// TagInfoTag selects the public account tag; WotsInfoTag a stage's 67
	// chain secrets. The Ed25519 seed uses rotatinghybrid.Ed25519InfoTag.
	TagInfoTag  byte = 0x10
	WotsInfoTag byte = 0x11

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
}

// DeriveStage derives stage i's keys and program.
func DeriveStage(d *rotatinghybrid.Deriver, i uint64) (*StageKeys, stage.Program, error) {
	if d == nil {
		return nil, stage.Program{}, errors.New("rotating wots deriver is nil")
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
	if err := d.ExpandStage(rotatinghybrid.Ed25519InfoTag, i, edSeed[:]); err != nil {
		keys.Zero()
		return nil, stage.Program{}, err
	}
	keys.ed25519 = ed25519.NewKeyFromSeed(edSeed[:])
	crypto.ZeroBytes(edSeed[:])
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
func (k *StageKeys) PublicKeys() stage.PublicKeys {
	var pub stage.PublicKeys
	pub.Tweak = k.tweak
	pub.Wots = k.wotsPub
	copy(pub.Ed25519[:], k.ed25519.Public().(ed25519.PublicKey))
	return pub
}

// Sign returns the stage's argument 0 (WOTS) and argument 1 (Ed25519)
// signatures over message, which for a spend is the raw 32-byte transaction
// ID. A stage must sign one message only.
func (k *StageKeys) Sign(message []byte) (wotsSig, ed25519Sig []byte, err error) {
	sig, err := wots.Sign(&k.tweak, k.wots, message)
	if err != nil {
		return nil, nil, fmt.Errorf("sign with stage WOTS key: %w", err)
	}
	return sig, ed25519.Sign(k.ed25519, message), nil
}

// Zero overwrites both private keys.
func (k *StageKeys) Zero() {
	if k == nil {
		return
	}
	crypto.ZeroBytes(k.wots)
	crypto.ZeroBytes(k.ed25519)
}

// Verify checks both signatures against the constants embedded in a stage
// program, as the AVM program will.
func Verify(keys stage.PublicKeys, message, wotsSig, ed25519Sig []byte) error {
	if err := wots.Verify(&keys.Tweak, keys.Wots, message, wotsSig); err != nil {
		return fmt.Errorf("stage WOTS signature: %w", err)
	}
	if !ed25519.Verify(keys.Ed25519[:], message, ed25519Sig) {
		return errors.New("stage Ed25519 signature is invalid")
	}
	return nil
}
