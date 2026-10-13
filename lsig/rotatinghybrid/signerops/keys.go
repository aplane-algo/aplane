// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerops holds the signer-side private-key operations of the
// aplane.rotating-hybrid.v1 key type: stage key generation from derived seeds
// and the paired Falcon-1024 and Ed25519 signatures over a transaction ID.
//
// It links the CGo Falcon implementation and must stay out of client
// binaries; the client-safe program layout lives in package stage.
package signerops

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/lsig/rotatinghybrid/stage"

	"github.com/algorand/falcon"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

// StageKeys are the private keys of one stage. Callers must Zero them.
type StageKeys struct {
	falcon  falcongo.KeyPair
	ed25519 ed25519.PrivateKey
}

// GenerateStageKeys derives a stage's key pairs from its seeds. Falcon uses
// the deterministic Falcon-1024 key generation seeded with the 48-byte stage
// seed; Ed25519 uses the RFC 8032 seed directly.
func GenerateStageKeys(seeds *rotatinghybrid.StageSeeds) (*StageKeys, error) {
	if seeds == nil {
		return nil, errors.New("rotating hybrid stage seeds are nil")
	}
	kp, err := falcongo.GenerateKeyPair(seeds.Falcon[:])
	if err != nil {
		return nil, fmt.Errorf("generate stage Falcon key: %w", err)
	}
	return &StageKeys{
		falcon:  kp,
		ed25519: ed25519.NewKeyFromSeed(seeds.Ed25519[:]),
	}, nil
}

// PublicKeys returns the keys a stage program embeds.
func (k *StageKeys) PublicKeys() stage.PublicKeys {
	var pub stage.PublicKeys
	copy(pub.Falcon[:], k.falcon.PublicKey[:])
	copy(pub.Ed25519[:], k.ed25519.Public().(ed25519.PublicKey))
	return pub
}

// Sign returns the stage's argument 0 (Falcon) and argument 1 (Ed25519)
// signatures over message, which for a spend is the raw 32-byte transaction ID.
func (k *StageKeys) Sign(message []byte) (falconSig, ed25519Sig []byte, err error) {
	sig, err := k.falcon.Sign(message)
	if err != nil {
		return nil, nil, fmt.Errorf("sign with stage Falcon key: %w", err)
	}
	return sig, ed25519.Sign(k.ed25519, message), nil
}

// Zero overwrites both private keys.
func (k *StageKeys) Zero() {
	if k == nil {
		return
	}
	crypto.ZeroBytes(k.falcon.PrivateKey[:])
	crypto.ZeroBytes(k.ed25519)
}

// Verify checks both signatures against the public keys embedded in a stage
// program, as the AVM's falcon_verify and ed25519verify_bare will.
func Verify(keys stage.PublicKeys, message, falconSig, ed25519Sig []byte) error {
	if len(falconSig) > stage.FalconSignatureMaxSize {
		return fmt.Errorf("stage Falcon signature is %d bytes, maximum is %d", len(falconSig), stage.FalconSignatureMaxSize)
	}
	if err := falcongo.Verify(message, falcon.CompressedSignature(falconSig), falcon.PublicKey(keys.Falcon)); err != nil {
		return fmt.Errorf("stage Falcon signature: %w", err)
	}
	if !ed25519.Verify(keys.Ed25519[:], message, ed25519Sig) {
		return errors.New("stage Ed25519 signature is invalid")
	}
	return nil
}

// DeriveStage derives stage i's keys and program in one step.
func DeriveStage(d *rotatinghybrid.Deriver, i uint64) (*StageKeys, stage.Program, error) {
	seeds, err := d.Stage(i)
	if err != nil {
		return nil, stage.Program{}, err
	}
	defer seeds.Zero()

	keys, err := GenerateStageKeys(&seeds)
	if err != nil {
		return nil, stage.Program{}, err
	}
	program, err := stage.Build(keys.PublicKeys())
	if err != nil {
		keys.Zero()
		return nil, stage.Program{}, fmt.Errorf("build stage %d program: %w", i, err)
	}
	return keys, program, nil
}
