// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keystore provides encrypted key storage.
//
// FileKeyStore is the storage implementation; consumers use the concrete
// type directly. For session management and on-demand decryption, see the
// KeySession type in this package.
package keystore

import "errors"

// Common keystore errors
var (
	// ErrKeyNotFound indicates the requested key does not exist
	ErrKeyNotFound = errors.New("key not found")

	// ErrStoreLocked indicates the keystore is locked and requires unlock
	ErrStoreLocked = errors.New("keystore is locked")
)
