// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import familyops "github.com/aplane-algo/aplane/lsig/ecdsak1/family/ops"

// Ops exposes ECDSA secp256k1 signer-side keygen, signing, and mnemonic operations.
type Ops struct {
	base familyops.DSABase
}

func New(base familyops.DSABase) *Ops {
	if base == nil {
		base = familyops.ECDSAK1Base
	}
	return &Ops{base: base}
}

func (o *Ops) GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error) {
	return o.base.GenerateKeypair(seed)
}

func (o *Ops) Sign(privateKey []byte, message []byte) (signature []byte, err error) {
	return o.base.Sign(privateKey, message)
}

func (o *Ops) SeedFromMnemonic(words []string, passphrase string) ([]byte, error) {
	return o.base.SeedFromMnemonic(words, passphrase)
}

func (o *Ops) EntropyToMnemonic(entropy []byte) ([]string, error) {
	return o.base.EntropyToMnemonic(entropy)
}
