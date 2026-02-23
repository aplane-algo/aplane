// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package lsigprovider defines unified interfaces for all LogicSig providers.
//
// This package provides a single registry and interface hierarchy for both
// generic LogicSigs (timelock, hashlock) and DSA-based LogicSigs (falcon1024).
// Capability detection is done via Go interface embedding and type assertion.
//
// Interface hierarchy:
//   - LSigProvider: Base interface for all providers (identity, display, parameters)
//   - SigningProvider: Extends LSigProvider with cryptographic signing (DSA LSigs)
//   - MnemonicProvider: Extends SigningProvider with mnemonic support
//
// The Category() method returns either "generic_lsig" or "dsa_lsig" to indicate
// whether the provider requires cryptographic key material.
package lsigprovider

// LSigProvider is the base interface that ALL LogicSig providers implement.
// This provides identity, display, and parameter metadata for any LSig type.
type LSigProvider interface {
	// Identity
	KeyType() string // Versioned identifier (e.g., "timelock-v1", "falcon1024-v1")
	Family() string  // Family name without version (e.g., "timelock", "falcon1024")
	Version() int    // Version number (e.g., 1)

	// Category returns the LSig category.
	// Use the constants CategoryGenericLsig ("generic_lsig") or CategoryDSALsig ("dsa_lsig").
	Category() string

	// Display
	DisplayName() string  // Human-readable name (e.g., "Falcon-1024", "Timelock")
	Description() string  // Short description for UI
	DisplayColor() string // ANSI color code (e.g., "33" for yellow)

	// CreationParams returns parameter definitions for LSig creation.
	// For generic LSigs: recipient, unlock_round, etc.
	// For pure DSA LSigs: typically empty (public key is implicit).
	// For hybrid DSA LSigs: unlock_round, recipient, etc.
	CreationParams() []ParameterDef

	// ValidateCreationParams validates the provided creation parameters.
	ValidateCreationParams(params map[string]string) error

	// RuntimeArgs returns argument definitions needed at transaction signing time.
	// For generic LSigs: hashlock preimage, etc.
	// For DSA LSigs: typically empty (signature is generated automatically).
	RuntimeArgs() []RuntimeArgDef

	// BuildArgs assembles the LogicSig Args array in the correct order.
	// - signature: the cryptographic signature (nil for generic LSigs)
	// - runtimeArgs: user-provided args keyed by name (already decoded to bytes)
	// Returns the Args array ready for use in types.LogicSig.
	// This encapsulates the arg ordering convention for each provider type.
	BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error)
}

// SigningProvider extends LSigProvider with cryptographic signing capability.
// This is implemented by DSA-based LogicSigs (falcon1024, falcon-timelock, etc.)
// that require key material for signing transactions.
type SigningProvider interface {
	LSigProvider

	// CryptoSignatureSize returns the maximum cryptographic signature size in bytes.
	// Used for pre-signing fee estimation since fee depends on total transaction size.
	CryptoSignatureSize() int

	// GenerateKeypair generates a keypair from a seed.
	// The seed typically comes from mnemonic derivation (e.g., 64 bytes from BIP-39).
	GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error)

	// Sign signs a message with the private key.
	// Returns the cryptographic signature to be included in LogicSig args.
	Sign(privateKey, message []byte) (signature []byte, err error)

	// DeriveLsig derives the LogicSig bytecode and address from a public key.
	// The params argument allows passing additional parameters for hybrid schemes:
	//   - Pure DSA (falcon1024-v1): params is empty or ignored
	//   - Hybrid (falcon-timelock-v1): params contains unlock_round, recipient, etc.
	// Returns: (lsigBytecode, algorandAddress, error)
	DeriveLsig(publicKey []byte, params map[string]string) (lsigBytecode []byte, address string, err error)
}

// MnemonicProvider extends SigningProvider with mnemonic (seed phrase) support.
// This allows key recovery from human-readable word sequences.
type MnemonicProvider interface {
	SigningProvider

	// MnemonicScheme returns the mnemonic scheme (e.g., "bip39", "algorand").
	MnemonicScheme() string

	// MnemonicWordCount returns the expected number of words in the mnemonic.
	MnemonicWordCount() int

	// SeedFromMnemonic derives a seed from a mnemonic phrase and optional passphrase.
	SeedFromMnemonic(words []string, passphrase string) ([]byte, error)

	// EntropyToMnemonic converts entropy bytes to mnemonic words.
	EntropyToMnemonic(entropy []byte) ([]string, error)
}
