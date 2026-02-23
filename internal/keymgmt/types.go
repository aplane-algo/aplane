// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package keymgmt provides business logic for key management operations.
// This package is UI-agnostic and can be used by CLI, REPL, and TUI interfaces.
package keymgmt

// KeyInfo holds information about a key
type KeyInfo struct {
	Address  string
	KeyType  string
	FilePath string
}

// GenerateResult is the result of generating a new key
type GenerateResult struct {
	Address  string
	KeyType  string // Full versioned type: "falcon1024-v1" or "ed25519"
	Mnemonic string // For display to user (once)
	KeyFile  string // Path to saved key
}

// DeleteResult is the result of deleting a key
type DeleteResult struct {
	DeletedPath string // Path where the key was moved to
}

// ExportResult is the result of exporting a key's mnemonic
type ExportResult struct {
	Address    string
	KeyType    string // Full versioned type: "falcon1024-v1" or "ed25519"
	Mnemonic   string
	WordCount  int
	Parameters map[string]string // Creation parameters needed for address re-derivation (composeDSA types)
}

// ImportResult is the result of importing a key from mnemonic
type ImportResult struct {
	Address string
	KeyType string
	KeyFile string // Path to saved key
}

// ListResult is the result of listing keys
type ListResult struct {
	Keys []KeyInfo
}
