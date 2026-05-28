// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package family provides ECDSA secp256k1 family constants.
package family

// Family identity.
const Name = "ecdsak1"

// Key sizes.
const (
	PublicKeySize  = 64 // Uncompressed X||Y (32 + 32)
	PrivateKeySize = 32 // secp256k1 scalar D
)

// Signature properties.
const MaxSignatureSize = 64 // R||S

// Mnemonic properties.
const (
	MnemonicScheme    = "bip39"
	MnemonicWordCount = 24
)

// Display properties.
const DisplayColor = "95" // ANSI bright magenta (pink)
