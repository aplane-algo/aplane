// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package logicsigdsa provides a unified abstraction for LogicSig-based
// digital signature algorithms (DSAs) used in Algorand post-quantum transactions.
//
// This package implements a 2-level hierarchy:
//  1. LogicSigDSA interface - defines the contract for all LogicSig-based DSAs
//  2. Concrete implementations - e.g., falcon1024-v1, falcon-512-v1
//
// Version is part of the identity (not a parameter) because the same mnemonic
// with different derivation versions produces different addresses.
package logicsigdsa

// LogicSigDSA defines the interface for LogicSig-based signature algorithms.
// Each implementation represents a specific algorithm AND version combination.
//
// Examples: "falcon1024-v1", "falcon-512-v1", "falcon1024-v2"
//
// The version is embedded in the type identity because different versions
// produce different LogicSig bytecode, and therefore different addresses.
// They are fundamentally different key types.
type LogicSigDSA interface {
	// KeyType returns the full identifier including version (e.g., "falcon1024-v1")
	KeyType() string

	// Family returns the algorithm family without version (e.g., "falcon1024")
	Family() string

	// Version returns the derivation version number (e.g., 1 for "falcon1024-v1")
	Version() int

	// CryptoSignatureSize returns the maximum cryptographic signature size in bytes.
	// Used for pre-signing fee estimation since fee depends on total transaction size.
	CryptoSignatureSize() int

	// MnemonicScheme returns the mnemonic scheme ("bip39" or "algorand")
	MnemonicScheme() string

	// MnemonicWordCount returns the expected number of words in the mnemonic
	MnemonicWordCount() int

	// DisplayColor returns the ANSI color code for UI display (e.g., "33" for yellow)
	DisplayColor() string

	// GenerateKeypair generates a keypair from a seed.
	// The seed typically comes from mnemonic derivation.
	GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error)

	// DeriveLsig derives the LogicSig bytecode and address from a public key.
	// The version is implicit in the implementation type.
	// The params argument allows passing additional parameters for hybrid schemes:
	//   - Pure DSA (falcon1024-v1): params is empty or ignored
	//   - Hybrid (falcon-timelock-v1): params contains unlock_round, recipient, etc.
	// Returns: (lsigBytecode, algorandAddress, error)
	DeriveLsig(publicKey []byte, params map[string]string) (lsigBytecode []byte, address string, err error)

	// Sign signs a message with the private key.
	// Returns the cryptographic signature.
	Sign(privateKey []byte, message []byte) (signature []byte, err error)
}

// TEALGenerator is optionally implemented by LogicSigDSA types that can
// provide the TEAL source code for the LogicSig program.
// Used at key generation to store the TEAL source in the key file.
type TEALGenerator interface {
	GenerateTEAL(publicKey []byte, params map[string]string) (string, error)
}
