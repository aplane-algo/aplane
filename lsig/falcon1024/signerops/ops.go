// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

// Ops exposes Falcon-1024 signer-side keygen and signing operations.
type Ops struct{}

func New() *Ops {
	return &Ops{}
}

// GenerateKeypair generates a Falcon-1024 keypair from a seed.
// The seed typically comes from BIP-39 mnemonic derivation (64 bytes).
func (o *Ops) GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error) {
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Falcon keypair: %w", err)
	}
	return kp.PublicKey[:], kp.PrivateKey[:], nil
}

// Sign signs a message with a Falcon-1024 private key.
func (o *Ops) Sign(privateKey []byte, message []byte) (signature []byte, err error) {
	if len(privateKey) != family.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
			family.PrivateKeySize, len(privateKey))
	}

	var priv falcongo.PrivateKey
	copy(priv[:], privateKey)
	defer crypto.ZeroBytes(priv[:])

	// The falcongo library requires a KeyPair. The public key is not used for
	// signing, so it can stay zero-filled.
	var pub falcongo.PublicKey
	kp := falcongo.KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
	}
	defer crypto.ZeroBytes(kp.PrivateKey[:])

	sig, err := kp.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	return sig, nil
}
