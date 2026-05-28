// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package ops

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/lsig/ecdsak1/family"

	falconmnemonic "github.com/algorandfoundation/falcon-signatures/mnemonic"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// DSABase defines ECDSA secp256k1 metadata plus signer-side operations.
type DSABase interface {
	family.DSABase
	GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error)
	Sign(privateKey []byte, message []byte) (signature []byte, err error)
	SeedFromMnemonic(words []string, passphrase string) ([]byte, error)
	EntropyToMnemonic(entropy []byte) ([]string, error)
}

// ECDSAK1Base is the signer-capable secp256k1 DSA base.
var ECDSAK1Base DSABase = &ecdsaK1DSABase{}

type ecdsaK1DSABase struct {
	family.ECDSAK1Core
	Core
}

func (b *ecdsaK1DSABase) Name() string {
	return family.Name
}

func (b *ecdsaK1DSABase) PublicKeySize() int {
	return family.PublicKeySize
}

func (b *ecdsaK1DSABase) PrivateKeySize() int {
	return family.PrivateKeySize
}

// Core contains ECDSA secp256k1 signer-side cryptographic operations.
type Core struct{}

// GenerateKeypair derives a deterministic secp256k1 keypair from a seed.
// The derivation uses SHA-256 rejection sampling with a domain-separated
// counter, producing an identical public key for the same seed regardless
// of which secp256k1 library backs the primitive operations.
func (c *Core) GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error) {
	priv, err := derivePrivateKey(seed)
	if err != nil {
		return nil, nil, err
	}

	// Serialize the 32-byte scalar. We copy out of the library's internal
	// representation so the caller owns the bytes and the original can be
	// zeroed after use.
	privBytes := priv.Serialize()
	defer crypto.ZeroBytes(privBytes)

	pubUncompressed := priv.PubKey().SerializeUncompressed()
	if len(pubUncompressed) != 65 || pubUncompressed[0] != 0x04 {
		return nil, nil, fmt.Errorf("unexpected secp256k1 public key encoding")
	}

	pub := make([]byte, family.PublicKeySize)
	copy(pub, pubUncompressed[1:])

	privOut := make([]byte, family.PrivateKeySize)
	copy(privOut, privBytes)

	return pub, privOut, nil
}

// Sign signs a 32-byte message hash and returns R||S (64 bytes, low-S
// normalized). The returned signature format matches what the TEAL
// ecdsa_verify Secp256k1 opcode expects when the two halves are passed as
// separate logic-sig args.
func (c *Core) Sign(privateKey []byte, message []byte) (signature []byte, err error) {
	if len(privateKey) != family.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
			family.PrivateKeySize, len(privateKey))
	}
	if len(message) != 32 {
		return nil, fmt.Errorf("invalid message size: ecdsak1 requires 32-byte message hash, got %d", len(message))
	}

	privCopy := make([]byte, len(privateKey))
	copy(privCopy, privateKey)
	defer crypto.ZeroBytes(privCopy)

	priv := secp256k1.PrivKeyFromBytes(privCopy)

	// decred's ecdsa.Sign is RFC6979-deterministic and BIP0062-canonical
	// (low-S), so the returned signature is already in the form the TEAL
	// verifier expects. We only need to serialize R and S as big-endian
	// 32-byte scalars.
	sig := ecdsa.Sign(priv, message)
	r := sig.R()
	s := sig.S()
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	out := make([]byte, family.MaxSignatureSize)
	copy(out[:32], rBytes[:])
	copy(out[32:], sBytes[:])
	return out, nil
}

// SeedFromMnemonic derives a seed from BIP-39 mnemonic words.
func (c *Core) SeedFromMnemonic(words []string, passphrase string) ([]byte, error) {
	seedArray, err := falconmnemonic.SeedFromMnemonic(words, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to derive seed from mnemonic: %w", err)
	}
	return seedArray[:], nil
}

// EntropyToMnemonic converts entropy bytes to BIP-39 mnemonic words.
func (c *Core) EntropyToMnemonic(entropy []byte) ([]string, error) {
	words, err := falconmnemonic.EntropyToMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to convert entropy to mnemonic: %w", err)
	}
	return words, nil
}

// secp256k1Order is the order N of the secp256k1 curve. Valid private key
// scalars are in [1, N-1]. We hardcode it here so the rejection-sampling
// loop is independent of any particular library's internal constants.
var secp256k1Order = func() *big.Int {
	n, ok := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	if !ok {
		panic("ecdsak1: failed to initialize secp256k1 curve order")
	}
	return n
}()

// derivePrivateKey does SHA-256 rejection sampling over a counter to produce
// a secp256k1 scalar in [1, N-1] from an arbitrary seed. The SHA-256 domain
// separator and counter layout are part of the address derivation contract:
// changing them shifts every derived ecdsak1 address.
func derivePrivateKey(seed []byte) (*secp256k1.PrivateKey, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("seed is required")
	}

	const maxAttempts = 1024
	for i := uint32(0); i < maxAttempts; i++ {
		h := sha256.New()
		h.Write([]byte("aplane.ecdsak1.v1"))
		h.Write(seed)
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], i)
		h.Write(ctr[:])

		candidate := h.Sum(nil)
		k := new(big.Int).SetBytes(candidate)
		if k.Sign() > 0 && k.Cmp(secp256k1Order) < 0 {
			priv := secp256k1.PrivKeyFromBytes(candidate)
			crypto.ZeroBytes(candidate)
			return priv, nil
		}
		crypto.ZeroBytes(candidate)
	}

	return nil, fmt.Errorf("failed to derive valid secp256k1 key from seed")
}
