// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keystore provides encrypted key storage.
//
// FileKeyStore is the storage implementation; consumers use the concrete
// type directly. For session management and on-demand decryption, see the
// KeySession type in this package.
package keystore

import (
	"errors"
	"time"
)

// Common keystore errors
var (
	// ErrKeyNotFound indicates the requested key does not exist
	ErrKeyNotFound = errors.New("key not found")

	// ErrInvalidPassphrase indicates the passphrase is incorrect
	ErrInvalidPassphrase = errors.New("invalid passphrase")

	// ErrStoreLocked indicates the keystore is locked and requires unlock
	ErrStoreLocked = errors.New("keystore is locked")
)

// KeyMetadata contains non-sensitive information about a stored key
type KeyMetadata struct {
	// Address is the Algorand address derived from the public key
	Address string

	// KeyType identifies the key algorithm ("ed25519", "aplane.falcon1024.v1")
	KeyType string

	// CreatedAt is when the key was stored (if known)
	CreatedAt time.Time

	// StorageType indicates the backend ("file", "hsm", "cloud-kms")
	StorageType string

	// Exportable indicates whether key material can be exported
	// HSM and cloud KMS keys are typically not exportable
	Exportable bool

	// FilePath is the path to the key file (file backend only)
	FilePath string
}
