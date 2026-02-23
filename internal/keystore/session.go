// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keystore

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/signing"
)

// KeySession manages passphrase caching with on-demand key decryption.
// Keys are decrypted ONLY when needed (on-demand), not pre-loaded into memory.
// Session expiration is handled externally by the Signer's inactivity timer,
// which locks the signer (zeroing the master key) after a configurable timeout.
type KeySession struct {
	keyStore   KeyStore             // Key storage backend
	passphrase *crypto.SecureString // encrypted passphrase (only stored during session)
	lock       sync.RWMutex         // protects concurrent access
}

// NewKeySession creates a new key session backed by the given key store.
func NewKeySession(keyStore KeyStore) *KeySession {
	return &KeySession{
		keyStore: keyStore,
	}
}

// InitializeSession pre-initializes the session with a passphrase.
// This is typically called at startup after verifying the passphrase via terminal
// (which allows masked input, unlike HTTP-based prompts during signing).
func (s *KeySession) InitializeSession(passphrase []byte) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Store passphrase securely
	s.passphrase = crypto.NewSecureStringFromBytes(passphrase)
}

// GetKey retrieves a key for signing, prompting for passphrase if needed.
// This is the main method called by the signing handler.
//
// Security: Keys are decrypted on-demand, not pre-loaded. Only the specific
// key needed for signing is decrypted, minimizing memory exposure.
//
// promptFunc: function to prompt user for passphrase (returns []byte for secure zeroing)
func (s *KeySession) GetKey(address string, promptFunc func() ([]byte, error)) (*signing.KeyMaterial, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	ctx := context.Background()

	// Check if we need to prompt for passphrase
	if s.passphrase == nil || s.passphrase.IsEmpty() {
		passphrase, err := promptFunc()
		if err != nil {
			return nil, fmt.Errorf("failed to get passphrase: %w", err)
		}

		// Store passphrase for session (will be zeroed when session is destroyed)
		if s.passphrase != nil {
			s.passphrase.Destroy()
		}
		s.passphrase = crypto.NewSecureStringFromBytes(passphrase)
		crypto.ZeroBytes(passphrase)
	}

	// Decrypt only this specific key (not all keys)
	// Note: The passphrase was used to unlock the keystore at startup.
	// Now we just retrieve keys using the cached master key.
	return s.keyStore.Get(ctx, address)
}

// clearPassphrase securely zeroes the cached passphrase
func (s *KeySession) clearPassphrase() {
	if s.passphrase != nil {
		s.passphrase.Destroy()
		s.passphrase = nil
	}
}

// Destroy clears the passphrase and destroys the session
// Call this when shutting down the server
// Uses a timeout to avoid hanging if a request is still in progress
func (s *KeySession) Destroy() {
	// Try to acquire lock with timeout to avoid hanging during shutdown
	done := make(chan struct{})
	go func() {
		s.lock.Lock()
		s.clearPassphrase()
		s.lock.Unlock()
		close(done)
	}()

	// Wait up to 2 seconds for cleanup, then force exit
	select {
	case <-done:
		// Clean shutdown
	case <-time.After(2 * time.Second):
		// Timeout - a request is still holding the lock
		// This is acceptable during forced shutdown
		fmt.Println("Warning: KeySession cleanup timed out (request still in progress)")
	}
}
