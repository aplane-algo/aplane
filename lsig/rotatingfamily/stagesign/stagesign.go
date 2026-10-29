// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package stagesign holds the stage signing the rotating key types share:
// each stage's Ed25519 and Falcon-1024 keys, the check of their signatures,
// the stage message rule and the wiping of signature buffers. A key type
// keeps the hash-based half of its stage and calls into this package for the
// rest. It does not depend on registration or key storage.
//
// Buffer ownership: ClassicalKeys owns its private keys until Zero, and
// DeriveClassicalKeys zeroes whatever it has derived when a later step fails.
// Sign returns new signature buffers, which the caller owns; when it fails it
// returns none. A key type that has already made its hash-based signature
// wipes it when Sign fails, and a stage operation that fails after signing
// wipes every signature it made (ZeroArgs).
package stagesign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/falconparams"

	"github.com/algorand/falcon"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

// MessageSize is the size of every message a stage signs: a raw 32-byte
// transaction ID, or the open-test message.
const MessageSize = 32

// newEd25519Key and generateFalconKeyPair derive the keys from their seeds;
// tests replace them to observe and fail derivation.
var (
	newEd25519Key         = ed25519.NewKeyFromSeed
	generateFalconKeyPair = falcongo.GenerateKeyPair
)

// CheckMessage refuses a message that is not MessageSize bytes.
func CheckMessage(message []byte) error {
	if len(message) != MessageSize {
		return fmt.Errorf("stage message is %d bytes, want a %d-byte transaction ID", len(message), MessageSize)
	}
	return nil
}

// OpenTestMessage is the fixed message a key type's open test signs, the
// SHA-256 of its derivation label followed by " stage open test". It is the
// hash of a label, not a transaction ID, so a signature over it cannot
// authorize anything.
func OpenTestMessage(label string) []byte {
	sum := sha256.Sum256([]byte(label + " stage open test"))
	return sum[:]
}

// ClassicalKeys are one stage's Ed25519 and Falcon-1024 private keys.
// Callers must Zero them.
type ClassicalKeys struct {
	ed25519 ed25519.PrivateKey
	falcon  falcongo.KeyPair
}

// DeriveClassicalKeys derives stage i's Ed25519 key from the seed d expands
// under ed25519Tag and its Falcon-1024 key from the seed under falconTag.
// Both seeds are zeroed once used; if a step fails, the keys derived before
// it are zeroed too.
func DeriveClassicalKeys(d *rotatinghybrid.Deriver, i uint64, ed25519Tag, falconTag byte) (*ClassicalKeys, error) {
	k := &ClassicalKeys{}
	var edSeed [rotatinghybrid.Ed25519SeedSize]byte
	if err := d.ExpandStage(ed25519Tag, i, edSeed[:]); err != nil {
		return nil, err
	}
	k.ed25519 = newEd25519Key(edSeed[:])
	crypto.ZeroBytes(edSeed[:])
	var falconSeed [rotatinghybrid.FalconSeedSize]byte
	if err := d.ExpandStage(falconTag, i, falconSeed[:]); err != nil {
		k.Zero()
		return nil, err
	}
	var err error
	k.falcon, err = generateFalconKeyPair(falconSeed[:])
	crypto.ZeroBytes(falconSeed[:])
	if err != nil {
		k.Zero()
		return nil, fmt.Errorf("generate stage %d Falcon key: %w", i, err)
	}
	return k, nil
}

// PublicKeys returns the Ed25519 and Falcon-1024 public keys a stage program
// embeds.
func (k *ClassicalKeys) PublicKeys() (ed25519Key [ed25519.PublicKeySize]byte, falconKey [falconparams.PublicKeySize]byte) {
	copy(ed25519Key[:], k.ed25519.Public().(ed25519.PublicKey))
	copy(falconKey[:], k.falcon.PublicKey[:])
	return ed25519Key, falconKey
}

// Sign signs message, which must be MessageSize bytes, with the Falcon-1024
// key and then the Ed25519 key, and returns the two signatures in new
// buffers. When it fails it returns none: Falcon signing is the only step
// that can fail, and it runs first.
func (k *ClassicalKeys) Sign(message []byte) (ed25519Sig, falconSig []byte, err error) {
	if err := CheckMessage(message); err != nil {
		return nil, nil, err
	}
	sig, err := k.falcon.Sign(message)
	if err != nil {
		return nil, nil, fmt.Errorf("sign with stage Falcon key: %w", err)
	}
	return ed25519.Sign(k.ed25519, message), sig, nil
}

// Zero overwrites both private keys. It is safe on a nil receiver and safe
// to call more than once.
func (k *ClassicalKeys) Zero() {
	if k == nil {
		return
	}
	crypto.ZeroBytes(k.ed25519)
	crypto.ZeroBytes(k.falcon.PrivateKey[:])
}

// VerifyClassical checks a stage's Ed25519 and Falcon-1024 signatures over
// message against the public keys its program embeds, as the AVM program
// will, including the cap on the compressed Falcon signature's size.
func VerifyClassical(ed25519Key *[ed25519.PublicKeySize]byte, falconKey *[falconparams.PublicKeySize]byte, message, ed25519Sig, falconSig []byte) error {
	if ed25519Key == nil || falconKey == nil {
		return errors.New("stage public keys are nil")
	}
	if err := CheckMessage(message); err != nil {
		return err
	}
	if !ed25519.Verify(ed25519Key[:], message, ed25519Sig) {
		return errors.New("stage Ed25519 signature is invalid")
	}
	if len(falconSig) > falconparams.CompressedSignatureMaxSize {
		return fmt.Errorf("stage Falcon signature is %d bytes, maximum is %d", len(falconSig), falconparams.CompressedSignatureMaxSize)
	}
	if err := falcongo.Verify(message, falcon.CompressedSignature(falconSig), falcon.PublicKey(*falconKey)); err != nil {
		return fmt.Errorf("stage Falcon signature: %w", err)
	}
	return nil
}

// ZeroArgs overwrites every argument buffer.
func ZeroArgs(args [][]byte) {
	for _, a := range args {
		crypto.ZeroBytes(a)
	}
}
