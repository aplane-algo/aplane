// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package family

// DSABase defines the interface for a Falcon DSA base provider.
// It exposes the pure metadata needed by composed
// LogicSigs (ComposedDSA) that live in sub-packages (e.g., v1/).
type DSABase interface {
	Name() string
	PublicKeySize() int
	PrivateKeySize() int
	CryptoSignatureSize() int
	MnemonicScheme() string
	MnemonicWordCount() int
	DisplayColor() string
}

// FalconBase is the Falcon-1024 DSA base for composed LogicSigs.
// It provides pure metadata for Falcon-1024 signature verification.
var FalconBase DSABase = &falconDSABase{}

// falconDSABase embeds FalconCore for shared metadata and adds
// the Name/PublicKeySize/PrivateKeySize methods required by DSABase.
type falconDSABase struct {
	FalconCore
}

func (b *falconDSABase) Name() string {
	return Name
}

func (b *falconDSABase) PublicKeySize() int {
	return PublicKeySize
}

func (b *falconDSABase) PrivateKeySize() int {
	return PrivateKeySize
}
