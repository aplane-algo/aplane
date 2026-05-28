// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

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
	KeyType  string // Full versioned type: "aplane.falcon1024.v1" or "ed25519"
	Mnemonic string // Internal recovery material persisted to the encrypted keyfile.
	KeyFile  string // Path to saved key
}

// DeleteResult is the result of deleting a key
type DeleteResult struct {
	DeletedPath string // Path where the key was moved to
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
