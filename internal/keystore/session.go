// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystore

import (
	"context"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/signing"
)

// KeySession manages on-demand key decryption using the master key.
// Keys are decrypted ONLY when needed (on-demand), not pre-loaded into memory.
// Session expiration is handled externally by explicit signer lock paths, which
// zero the master key and destroy the active key session.
type KeySession struct {
	keyStore KeyStore     // Key storage backend
	active   bool         // Whether the session is active (master key available)
	lock     sync.RWMutex // protects concurrent access
}

// NewKeySession creates a new key session backed by the given key store.
func NewKeySession(keyStore KeyStore) *KeySession {
	return &KeySession{
		keyStore: keyStore,
	}
}

// InitializeSession marks the session as active.
// This is called after the master key has been derived and stored in the keystore.
func (s *KeySession) InitializeSession() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.active = true
}

// GetKey retrieves a key for signing.
// The session must be active (master key available in the keystore).
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

	// Decrypt only this specific key using the cached master key
	return s.keyStore.Get(ctx, address)
}

// clearSession deactivates the session
func (s *KeySession) clearSession() {
	s.active = false
}

// Destroy clears the session state.
// Call this when shutting down the server.
// Blocks until any in-flight GetKey (which holds the lock) finishes.
// With RLock held during decryption in FileKeyStore, ClearMasterKey()
// naturally waits for in-flight operations to complete.
func (s *KeySession) Destroy() {
	s.lock.Lock()
	s.clearSession()
	s.lock.Unlock()
}
