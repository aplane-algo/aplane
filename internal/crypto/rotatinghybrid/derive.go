// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package rotatinghybrid derives the per-stage key seeds of the rotating
// account key type aplane.rotating-triple-wots.v1 (and, under their own
// labels, any rotating key type added later).
//
// One BIP-39 seed controls one account on one network. Every stage's key
// seeds are expanded from it with HKDF-SHA-512, bound to the key type's
// label, the network genesis hash and the stage number, so the only link
// between stages is a one-way hash. This package owns the derivation; it
// lives under internal/crypto because key-derivation primitives are confined
// here.
//
// The derivation is a frozen v1 contract: changing any constant changes every
// account address and requires a new key type.
package rotatinghybrid

import (
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"

	falconmnemonic "github.com/algorandfoundation/falcon-signatures/mnemonic"
)

const (
	// DerivationLabel is the HKDF salt that domain-separates this key type
	// from every other use of the same mnemonic.
	DerivationLabel = "APLANE_ROTATING_HYBRID_V1"

	// MnemonicWordCount is the only supported mnemonic length (256 bits of
	// entropy), matching APlane's existing BIP-39 encoding.
	MnemonicWordCount = 24

	// SeedSize is the size of the BIP-39 seed the stage chain derives from.
	SeedSize = 64

	// GenesisHashSize is the size of an Algorand genesis hash.
	GenesisHashSize = 32

	// FalconSeedSize is the seed length passed to Falcon-1024 key generation.
	FalconSeedSize = 48

	// Ed25519SeedSize is the RFC 8032 Ed25519 private seed length.
	Ed25519SeedSize = 32

	bip39Iterations = 2048
	bip39SaltPrefix = "mnemonic"

	falconInfoTag byte = 0x01

	// Ed25519InfoTag selects a stage's Ed25519 seed. Both rotating key types
	// use it under their own labels.
	Ed25519InfoTag byte = 0x02
)

// ErrInvalidMnemonic reports a mnemonic that is not a valid 24-word BIP-39
// English phrase.
var ErrInvalidMnemonic = errors.New("invalid rotating hybrid mnemonic")

// Seed is the 64-byte BIP-39 seed that controls a rotating hybrid account.
type Seed [SeedSize]byte

// Zero overwrites the seed.
func (s *Seed) Zero() {
	crypto.ZeroBytes(s[:])
}

// StageSeeds holds the two key-generation seeds of one stage.
type StageSeeds struct {
	Falcon  [FalconSeedSize]byte
	Ed25519 [Ed25519SeedSize]byte
}

// Zero overwrites both stage seeds.
func (s *StageSeeds) Zero() {
	crypto.ZeroBytes(s.Falcon[:])
	crypto.ZeroBytes(s.Ed25519[:])
}

// SeedFromMnemonic validates a 24-word BIP-39 English mnemonic, including its
// checksum, and returns its standard BIP-39 seed:
// PBKDF2-HMAC-SHA512(sentence, "mnemonic", 2048 iterations, 64 bytes).
//
// No BIP-39 passphrase is supported in v1. The English wordlist is ASCII, so
// the NFKD normalization BIP-39 requires leaves the sentence unchanged.
func SeedFromMnemonic(words []string) (Seed, error) {
	if len(words) != MnemonicWordCount {
		return Seed{}, fmt.Errorf("%w: got %d words, want %d", ErrInvalidMnemonic, len(words), MnemonicWordCount)
	}
	entropy, err := falconmnemonic.MnemonicToEntropy(words)
	if err != nil {
		// The library error can quote a mnemonic word, so it is not wrapped.
		return Seed{}, fmt.Errorf("%w: unknown word or checksum mismatch", ErrInvalidMnemonic)
	}
	crypto.ZeroBytes(entropy)

	// The words arrive as immutable strings, so the sentence cannot be zeroed
	// here; callers own the lifetime of the mnemonic itself.
	sentence := strings.Join(words, " ")
	derived, err := pbkdf2.Key(sha512.New, sentence, []byte(bip39SaltPrefix), bip39Iterations, SeedSize)
	if err != nil {
		return Seed{}, fmt.Errorf("derive BIP-39 seed: %w", err)
	}
	defer crypto.ZeroBytes(derived)

	var seed Seed
	copy(seed[:], derived)
	return seed, nil
}

// NewMnemonic returns a fresh 24-word mnemonic from 256 bits of
// crypto/rand entropy, and the seed it derives. The caller shows the words to
// the operator once and must zero the seed.
func NewMnemonic() ([]string, Seed, error) {
	entropy := make([]byte, 32)
	defer crypto.ZeroBytes(entropy)
	if _, err := rand.Read(entropy); err != nil {
		return nil, Seed{}, fmt.Errorf("read entropy: %w", err)
	}
	words, err := falconmnemonic.EntropyToMnemonic(entropy)
	if err != nil {
		return nil, Seed{}, fmt.Errorf("encode mnemonic: %w", err)
	}
	seed, err := SeedFromMnemonic(words)
	if err != nil {
		return nil, Seed{}, err
	}
	return words, seed, nil
}

// Deriver expands stage seeds for one account on one network. It holds the
// HKDF pseudorandom key, so callers must Zero it when done.
type Deriver struct {
	prk         []byte
	genesisHash [GenesisHashSize]byte
}

// NewDeriver binds a seed to a network under the rotating hybrid label. The
// seed is not retained.
func NewDeriver(seed *Seed, genesisHash [GenesisHashSize]byte) (*Deriver, error) {
	return NewDeriverWithLabel(seed, genesisHash, DerivationLabel)
}

// NewDeriverWithLabel binds a seed to a network under a key type's own HKDF
// salt, so two rotating key types never share stage material from one seed.
// The seed is not retained.
func NewDeriverWithLabel(seed *Seed, genesisHash [GenesisHashSize]byte, label string) (*Deriver, error) {
	if seed == nil {
		return nil, errors.New("rotating seed is nil")
	}
	if label == "" {
		return nil, errors.New("rotating derivation label is empty")
	}
	prk, err := hkdf.Extract(sha512.New, seed[:], []byte(label))
	if err != nil {
		return nil, fmt.Errorf("extract rotating key: %w", err)
	}
	return &Deriver{prk: prk, genesisHash: genesisHash}, nil
}

// OpenDeriver binds a stored seed and genesis hash, as a key file holds
// them, under label. It checks both lengths and zeroes its copy of the seed
// before returning; the caller keeps ownership of seed and must Zero the
// deriver.
func OpenDeriver(seed, genesisHash []byte, label string) (*Deriver, error) {
	var s Seed
	var g [GenesisHashSize]byte
	if len(seed) != len(s) || len(genesisHash) != len(g) {
		return nil, fmt.Errorf("rotating seed or genesis hash has the wrong length (%d and %d bytes, want %d and %d)", len(seed), len(genesisHash), len(s), len(g))
	}
	copy(s[:], seed)
	defer s.Zero()
	copy(g[:], genesisHash)
	return NewDeriverWithLabel(&s, g, label)
}

// Stage returns the Falcon and Ed25519 seeds of stage i:
//
//	falcon_seed_i  = HKDF-Expand(PRK, 0x01 || G || u64be(i), 48)
//	ed25519_seed_i = HKDF-Expand(PRK, 0x02 || G || u64be(i), 32)
func (d *Deriver) Stage(i uint64) (StageSeeds, error) {
	if d == nil || d.prk == nil {
		return StageSeeds{}, errors.New("rotating hybrid deriver is not initialized")
	}
	var out StageSeeds
	if err := d.ExpandStage(falconInfoTag, i, out.Falcon[:]); err != nil {
		return StageSeeds{}, err
	}
	if err := d.ExpandStage(Ed25519InfoTag, i, out.Ed25519[:]); err != nil {
		out.Zero()
		return StageSeeds{}, err
	}
	return out, nil
}

// ExpandAccount fills dst with account-level material that no stage owns:
// HKDF-Expand(PRK, tag || G, len(dst)).
func (d *Deriver) ExpandAccount(tag byte, dst []byte) error {
	if d == nil || d.prk == nil {
		return errors.New("rotating deriver is not initialized")
	}
	info := make([]byte, 0, 1+GenesisHashSize)
	info = append(info, tag)
	info = append(info, d.genesisHash[:]...)
	return d.expandInfo(info, dst)
}

// ExpandStage fills dst with stage material:
// HKDF-Expand(PRK, tag || G || u64be(stage), len(dst)).
func (d *Deriver) ExpandStage(tag byte, stage uint64, dst []byte) error {
	if d == nil || d.prk == nil {
		return errors.New("rotating deriver is not initialized")
	}
	info := make([]byte, 0, 1+GenesisHashSize+8)
	info = append(info, tag)
	info = append(info, d.genesisHash[:]...)
	info = binary.BigEndian.AppendUint64(info, stage)
	return d.expandInfo(info, dst)
}

// GenesisHash returns the network the deriver is bound to.
func (d *Deriver) GenesisHash() [GenesisHashSize]byte {
	return d.genesisHash
}

// Zero overwrites the pseudorandom key. The deriver is unusable afterwards.
func (d *Deriver) Zero() {
	if d == nil {
		return
	}
	crypto.ZeroBytes(d.prk)
	d.prk = nil
}

func (d *Deriver) expandInfo(info []byte, dst []byte) error {
	expanded, err := hkdf.Expand(sha512.New, d.prk, string(info), len(dst))
	if err != nil {
		return fmt.Errorf("expand rotating material: %w", err)
	}
	copy(dst, expanded)
	crypto.ZeroBytes(expanded)
	return nil
}
