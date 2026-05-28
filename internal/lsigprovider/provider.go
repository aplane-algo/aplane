// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package lsigprovider defines unified interfaces for all LogicSig providers.
//
// This package provides a single registry for both generic LogicSigs
// (timelock, htlc) and DSA-based LogicSigs (falcon1024).
//
// Interface hierarchy:
//   - LSigProvider: Base interface for all providers (identity, display, parameters)
//   - SigningProvider: Extends LSigProvider with signature metadata and derivation
//   - MnemonicProvider: Extends SigningProvider with mnemonic metadata
//
// The Category() method returns either "generic_lsig" or "dsa_lsig" to indicate
// whether the provider requires cryptographic key material.
package lsigprovider

import "context"

// LSigProvider is the base interface that ALL LogicSig providers implement.
// This provides identity, display, and parameter metadata for any LSig type.
type LSigProvider interface {
	// Identity
	KeyType() string // Versioned identifier (e.g., "aplane.timelock.v1", "aplane.falcon1024.v1")
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
	// For generic LSigs: HTLC preimage, etc.
	// For DSA LSigs: typically empty (signature is generated automatically).
	RuntimeArgs() []RuntimeArgDef

	// BuildArgs assembles the LogicSig Args array in the correct order.
	// - signature: the cryptographic signature (nil for generic LSigs)
	// - runtimeArgs: user-provided args keyed by name (already decoded to bytes)
	// Returns the Args array ready for use in types.LogicSig.
	// This encapsulates the arg ordering convention for each provider type.
	BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error)
}

// CompatibilityFingerprinter is implemented by providers that can expose a
// stable semantic fingerprint for their compatibility-bearing definition.
//
// This is used to distinguish idempotent same-definition reloads from
// conflicting same-key-type mutations.
type CompatibilityFingerprinter interface {
	CompatibilityFingerprint() string
}

// SigningProvider extends LSigProvider with DSA signature metadata and
// derivation. Private-key signing and key generation are intentionally not part
// of this client-visible interface; they live in signer-side registries.
type SigningProvider interface {
	LSigProvider

	// CryptoSignatureSize returns the maximum cryptographic signature size in bytes.
	// Used for pre-signing fee estimation since fee depends on total transaction size.
	CryptoSignatureSize() int

	// DeriveLsig derives the LogicSig bytecode and address from a public key.
	// The params argument allows passing additional parameters for hybrid schemes:
	//   - Pure DSA (aplane.falcon1024.v1): params is empty or ignored
	//   - Hybrid (falcon-aplane.timelock.v1): params contains unlock_round, recipient, etc.
	// Returns: (lsigBytecode, algorandAddress, error)
	DeriveLsig(ctx context.Context, publicKey []byte, params map[string]string) (lsigBytecode []byte, address string, err error)
}

// MnemonicProvider extends SigningProvider with mnemonic metadata. Mnemonic
// generation/export execution is handled by the signer-side mnemonic registry.
// SupportsMnemonicImport is separate from MnemonicWordCount because some key
// types can derive from mnemonic material internally but should not accept
// user-entered mnemonics.
type MnemonicProvider interface {
	SigningProvider

	// MnemonicScheme returns the mnemonic scheme (e.g., "bip39", "algorand").
	MnemonicScheme() string

	// MnemonicWordCount returns the expected number of words in the mnemonic.
	MnemonicWordCount() int

	// SupportsMnemonicImport returns true when user-entered mnemonic import is supported.
	SupportsMnemonicImport() bool
}
