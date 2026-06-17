// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"crypto/ed25519"
	"fmt"

	"github.com/aplane-algo/aplane/lsig/ed25519lsig/family"
)

type Ops struct{}

func New() *Ops {
	return &Ops{}
}

func (o *Ops) GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error) {
	var sk ed25519.PrivateKey
	switch len(seed) {
	case ed25519.SeedSize:
		sk = ed25519.NewKeyFromSeed(seed)
	case ed25519.PrivateKeySize:
		sk = ed25519.PrivateKey(append([]byte(nil), seed...))
	default:
		return nil, nil, fmt.Errorf("invalid Ed25519 seed length %d", len(seed))
	}
	pub := sk.Public().(ed25519.PublicKey)
	return append([]byte(nil), pub...), append([]byte(nil), sk...), nil
}

func (o *Ops) Sign(privateKey []byte, message []byte) ([]byte, error) {
	if len(privateKey) != family.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size: expected %d, got %d", family.PrivateKeySize, len(privateKey))
	}
	return ed25519.Sign(ed25519.PrivateKey(privateKey), message), nil
}
