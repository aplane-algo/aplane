// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package derivation provides versioned LogicSig derivation for Falcon keys.
//
// Falcon addresses are derived from LogicSig bytecode (SHA-512/256 hash).
// If the TEAL template changes, addresses change, breaking mnemonic recovery.
// This package vendors each derivation version to ensure stability.
//
// Version History:
//   - v1: falcon-signatures v1.1.1 (TEAL v12, falcon_verify opcode)
package derivation

// CurrentVersion is the derivation version used for new keys.
// Increment when adding a new version.
const CurrentVersion = 1

// SupportedVersions returns all supported derivation versions.
func SupportedVersions() []int {
	return []int{1}
}
