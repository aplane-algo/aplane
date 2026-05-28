// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package family

// DSABase defines ECDSA secp256k1 family metadata.
type DSABase interface {
	Name() string
	PublicKeySize() int
	PrivateKeySize() int
	CryptoSignatureSize() int
	MnemonicScheme() string
	MnemonicWordCount() int
	DisplayColor() string
}

// ECDSAK1Base is the secp256k1 metadata singleton.
var ECDSAK1Base DSABase = &ecdsaK1DSABase{}

type ecdsaK1DSABase struct {
	ECDSAK1Core
}

func (b *ecdsaK1DSABase) Name() string        { return Name }
func (b *ecdsaK1DSABase) PublicKeySize() int  { return PublicKeySize }
func (b *ecdsaK1DSABase) PrivateKeySize() int { return PrivateKeySize }
