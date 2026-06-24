// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package family provides Falcon-1024 family constants.
// This is a separate package to avoid import cycles between
// dsa/falcon1024 and its sub-packages.
package family

// Family identity. This is the qualified registry family ("publisher.family"),
// used as the key in the keygen/mnemonic/metadata/signing registries. It is
// intentionally distinct from any future native "falcon1024" key type.
const Name = "aplane.falcon1024"

// Key sizes (from the falcongo library)
const (
	PublicKeySize  = 1793
	PrivateKeySize = 2305
)

// Signature properties
const MaxSignatureSize = 1280 // Falcon-1024 max signature size in bytes

// Mnemonic properties
const (
	MnemonicScheme    = "bip39"
	MnemonicWordCount = 24 // BIP-39 with 256 bits of entropy
)

// Display properties
const DisplayColor = "33" // ANSI yellow
