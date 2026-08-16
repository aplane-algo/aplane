// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package family provides Falcon-1024 family constants.
// This is a separate package to avoid import cycles between
// dsa/falcon1024 and its sub-packages.
package family

import "github.com/aplane-algo/aplane/internal/falconparams"

// Family identity. This is the qualified registry family ("publisher.family"),
// used as the key in the keygen/mnemonic/metadata/signing registries. It is
// intentionally distinct from any future native "falcon1024" key type.
const Name = "aplane.falcon1024"

// Key sizes (from the falcongo library)
const (
	PublicKeySize  = falconparams.PublicKeySize
	PrivateKeySize = falconparams.PrivateKeySize
)

// Signature properties
const MaxSignatureSize = falconparams.CompressedSignatureMaxSize

// Mnemonic properties
const (
	MnemonicScheme    = "bip39"
	MnemonicWordCount = 24 // BIP-39 with 256 bits of entropy
)

// Display properties
const DisplayColor = "33" // ANSI yellow
