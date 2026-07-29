// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystore

import (
	"context"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/signing"
)

// KeySession manages on-demand key decryption using the keyring.
// Keys are decrypted ONLY when needed (on-demand), not pre-loaded into memory.
// Session expiration is handled externally by explicit signer lock paths, which
// zero the term keys and destroy the active key session.
type KeySession struct {
	keyStore sessionKeyStore // Key storage backend
	active   bool            // Whether the session is active (keyring open)
	lock     sync.RWMutex    // protects concurrent access
}

// sessionKeyStore is the slice of the key store KeySession actually uses.
// Production passes *FileKeyStore; tests substitute a mock.
type sessionKeyStore interface {
	// Get retrieves the key material for signing. The keystore must be
	// unlocked; the caller zeroes the returned KeyMaterial after use.
	Get(ctx context.Context, address string) (*signing.KeyMaterial, error)
}

// NewKeySession creates a new key session backed by the given key store.
func NewKeySession(keyStore sessionKeyStore) *KeySession {
	return &KeySession{
		keyStore: keyStore,
	}
}

// InitializeSession marks the session as active.
// This is called after the keyring has been opened and held by the keystore.
func (s *KeySession) InitializeSession() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.active = true
}

// GetKey retrieves a key for signing.
// The session must be active (keyring open in the keystore).
//
// Security: Keys are decrypted on-demand, not pre-loaded. Only the specific
// key needed for signing is decrypted, minimizing memory exposure.
func (s *KeySession) GetKey(address string) (*signing.KeyMaterial, error) {
	return s.GetKeyWithContext(context.Background(), address)
}

// GetKeyWithContext retrieves a key for signing using the caller's context for
// keystore I/O and decryption.
func (s *KeySession) GetKeyWithContext(ctx context.Context, address string) (*signing.KeyMaterial, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if !s.active {
		return nil, fmt.Errorf("signer not unlocked - connect apadmin to unlock: %w", ErrStoreLocked)
	}

	// Decrypt only this specific key using the cached keyring
	return s.keyStore.Get(ctx, address)
}

// clearSession deactivates the session
func (s *KeySession) clearSession() {
	s.active = false
}

// Destroy clears the session state.
// Call this when shutting down the server.
// Blocks until any in-flight GetKey (which holds the lock) finishes.
// With RLock held during decryption in FileKeyStore, ClearKeys()
// naturally waits for in-flight operations to complete.
func (s *KeySession) Destroy() {
	s.lock.Lock()
	s.clearSession()
	s.lock.Unlock()
}
