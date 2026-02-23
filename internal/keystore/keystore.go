// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package keystore provides key storage interfaces and implementations.
//
// This package defines the KeyStore interface for abstracting key storage
// backends. The default implementation is file-based, with future support
// for HSM and cloud KMS backends.
//
// The KeyStore interface focuses on storage operations. For session management
// and passphrase caching, see the KeySession type in this package.
package keystore

import (
	"context"
	"errors"
	"time"

	"github.com/aplane-algo/aplane/internal/signing"
)

// Common keystore errors
var (
	// ErrKeyNotFound indicates the requested key does not exist
	ErrKeyNotFound = errors.New("key not found")

	// ErrKeyExists indicates a key already exists at the address
	ErrKeyExists = errors.New("key already exists")

	// ErrNotExportable indicates the key cannot be exported (e.g., HSM keys)
	ErrNotExportable = errors.New("key is not exportable")

	// ErrInvalidPassphrase indicates the passphrase is incorrect
	ErrInvalidPassphrase = errors.New("invalid passphrase")

	// ErrStoreLocked indicates the keystore is locked and requires unlock
	ErrStoreLocked = errors.New("keystore is locked")
)

// KeyMetadata contains non-sensitive information about a stored key
type KeyMetadata struct {
	// Address is the Algorand address derived from the public key
	Address string

	// KeyType identifies the key algorithm ("ed25519", "falcon1024-v1")
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

// KeyStore abstracts key storage and retrieval operations
//
// Implementations must be safe for concurrent use.
// The keystore must be unlocked before use (implementation-specific).
type KeyStore interface {
	// List returns metadata for all available keys.
	// This should not require decryption - only scan for key files/entries.
	List(ctx context.Context) ([]KeyMetadata, error)

	// Get retrieves the key material for signing.
	// The keystore must be unlocked before calling Get.
	// Caller is responsible for zeroing the returned KeyMaterial after use.
	Get(ctx context.Context, address string) (*signing.KeyMaterial, error)

	// GetMetadata returns metadata for a single key without decrypting it.
	GetMetadata(ctx context.Context, address string) (*KeyMetadata, error)

	// Delete removes a key from the store.
	// Returns ErrKeyNotFound if the key does not exist.
	Delete(ctx context.Context, address string) error

	// Type returns the storage backend type ("file", "hsm", "cloud-kms")
	Type() string
}
