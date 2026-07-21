// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package logicsigdsa provides a unified abstraction for LogicSig-based
// digital signature algorithms (DSAs) used in Algorand post-quantum transactions.
//
// This package implements a 2-level hierarchy:
//  1. LogicSigDSA interface - defines the contract for all LogicSig-based DSAs
//  2. Concrete implementations - e.g., aplane.falcon1024.v1, falcon-512-v1
//
// Version is part of the identity (not a parameter) because the same mnemonic
// with different derivation versions produces different addresses.
package logicsigdsa

import (
	"context"

	"github.com/aplane-algo/aplane/internal/lsigsalt"
)

// LogicSigDSA defines the interface for LogicSig-based signature algorithms.
// Each implementation represents a specific algorithm AND version combination.
//
// Examples: "aplane.falcon1024.v1", "falcon-512-v1", "falcon1024-v2"
//
// The version is embedded in the type identity because different versions
// produce different LogicSig bytecode, and therefore different addresses.
// They are fundamentally different key types.
type LogicSigDSA interface {
	// KeyType returns the full identifier including version (e.g., "aplane.falcon1024.v1")
	KeyType() string

	// RoutingFamily returns the algorithm family without version (e.g., "falcon1024")
	RoutingFamily() string

	// Version returns the derivation version number (e.g., 1 for "aplane.falcon1024.v1")
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

	// DeriveLsig derives the LogicSig bytecode and address from a public key.
	// The version is implicit in the implementation type.
	// The params argument allows passing additional parameters for hybrid schemes:
	//   - Pure DSA (aplane.falcon1024.v1): params is empty or ignored
	//   - Hybrid (falcon-aplane.htlc.v1): params contains unlock_round, recipients, etc.
	// Returns: (lsigBytecode, algorandAddress, error)
	DeriveLsig(ctx context.Context, publicKey []byte, params map[string]string) (lsigBytecode []byte, address string, err error)
}

// TEALGenerator is optionally implemented by LogicSigDSA types that can
// provide the TEAL source code for the LogicSig program.
// Used at key generation to store the TEAL source in the key file.
type TEALGenerator interface {
	GenerateTEAL(publicKey []byte, params map[string]string) (string, error)
}

// SaltedDeriver is implemented by LogicSigDSA types that can return the
// off-curve salt metadata used while deriving the LogicSig address. New DSA
// LogicSig key generation requires this interface so key files can persist the
// selected salt_counter without assuming a specific salt anchor style.
type SaltedDeriver interface {
	DeriveLsigWithSalt(ctx context.Context, publicKey []byte, params map[string]string) (lsigsalt.FindResult, error)
}
