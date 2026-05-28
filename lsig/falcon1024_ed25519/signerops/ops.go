// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconsignerops "github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	falconhybrid "github.com/aplane-algo/aplane/lsig/falcon1024_ed25519"
)

const ed25519SeedDomain = "aplane-falcon1024-ed25519-v1-ed25519-seed"

// Ops exposes signer-side operations for the dual Falcon-1024 / Ed25519 family.
type Ops struct {
	falcon *falconsignerops.Ops
}

func New() *Ops {
	return &Ops{falcon: falconsignerops.New(nil)}
}

func (o *Ops) GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error) {
	falconPub, falconPriv, err := o.falcon.GenerateKeypair(seed)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.ZeroBytes(falconPriv)

	edSeed := deriveEd25519Seed(seed)
	defer crypto.ZeroBytes(edSeed)
	edPriv := ed25519.NewKeyFromSeed(edSeed)
	defer crypto.ZeroBytes(edPriv)
	edPub, ok := edPriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("failed to derive Ed25519 public key")
	}

	publicKey = make([]byte, 0, falconhybrid.PublicKeySize)
	publicKey = append(publicKey, falconPub...)
	publicKey = append(publicKey, edPub...)

	privateKey = make([]byte, 0, falconhybrid.PrivateKeySize)
	privateKey = append(privateKey, falconPriv...)
	privateKey = append(privateKey, edPriv...)
	return publicKey, privateKey, nil
}

func (o *Ops) Sign(privateKey []byte, message []byte) (signature []byte, err error) {
	falconPriv, edPriv, err := splitPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	falconSig, err := o.falcon.Sign(falconPriv, message)
	if err != nil {
		return nil, err
	}

	edSig := ed25519.Sign(edPriv, message)
	if len(falconSig) > family.MaxSignatureSize {
		return nil, fmt.Errorf("falcon signature size %d exceeds maximum %d", len(falconSig), family.MaxSignatureSize)
	}

	signature = make([]byte, 2+len(falconSig)+len(edSig))
	binary.BigEndian.PutUint16(signature[:2], uint16(len(falconSig)))
	copy(signature[2:], falconSig)
	copy(signature[2+len(falconSig):], edSig)
	return signature, nil
}

func (o *Ops) SeedFromMnemonic(words []string, passphrase string) ([]byte, error) {
	return o.falcon.SeedFromMnemonic(words, passphrase)
}

func (o *Ops) EntropyToMnemonic(entropy []byte) ([]string, error) {
	return o.falcon.EntropyToMnemonic(entropy)
}

func deriveEd25519Seed(seed []byte) []byte {
	h := sha512.New()
	_, _ = h.Write([]byte(ed25519SeedDomain))
	_, _ = h.Write(seed)
	sum := h.Sum(nil)
	edSeed := append([]byte(nil), sum[:ed25519.SeedSize]...)
	crypto.ZeroBytes(sum)
	return edSeed
}

func splitPrivateKey(privateKey []byte) (falconPriv, edPriv []byte, err error) {
	if len(privateKey) != falconhybrid.PrivateKeySize {
		return nil, nil, fmt.Errorf("invalid private key size: expected %d, got %d",
			falconhybrid.PrivateKeySize, len(privateKey))
	}
	return privateKey[:family.PrivateKeySize], privateKey[family.PrivateKeySize:], nil
}
