// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package mnemonic

import (
	"fmt"
	"sort"
	"sync"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
)

// Handler defines the interface for mnemonic operations
type Handler interface {
	// Family returns the algorithm family this handler supports (e.g., "falcon1024", "ed25519")
	// This is distinct from LogicSigDSA.KeyType() which returns versioned types like "falcon1024-v1"
	Family() string

	// GenerateMnemonic generates a new mnemonic phrase
	// Returns: mnemonic words, seed bytes, entropy bytes (if applicable), error
	GenerateMnemonic() (words string, seed []byte, entropy []byte, err error)

	// SeedFromMnemonic derives a seed from mnemonic words
	// passphrase is optional and may be empty
	SeedFromMnemonic(words []string, passphrase string) ([]byte, error)

	// EntropyToMnemonic converts entropy bytes to mnemonic words
	// Not all handlers support this (e.g., Ed25519 doesn't use entropy)
	EntropyToMnemonic(entropy []byte) (string, error)

	// ValidateWordCount checks if the word count is valid for this mnemonic type
	ValidateWordCount(wordCount int) error

	// WordCount returns the expected number of words in the mnemonic
	WordCount() int
}

// HandlerRegistry manages mnemonic handlers for different key types
type HandlerRegistry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// Global registry instance
var registry = &HandlerRegistry{
	handlers: make(map[string]Handler),
}

// Register registers a mnemonic handler for an algorithm family
// This is idempotent - duplicate registrations are silently ignored
func Register(handler Handler) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	family := handler.Family()
	if _, exists := registry.handlers[family]; exists {
		// Already registered - silently ignore
		return
	}
	registry.handlers[family] = handler
}

// GetHandler retrieves a mnemonic handler by key type.
// Versioned types like "falcon1024-v1" are normalized to their family type.
func GetHandler(keyType string) (Handler, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	// Try direct lookup first
	if handler, exists := registry.handlers[keyType]; exists {
		return handler, nil
	}

	// Try family name (e.g., "falcon1024-v1" -> "falcon1024")
	family := logicsigdsa.GetFamily(keyType)
	if family != keyType {
		if handler, exists := registry.handlers[family]; exists {
			return handler, nil
		}
	}

	return nil, fmt.Errorf("no mnemonic handler registered for key type: %s", keyType)
}

// GetRegisteredFamilies returns a sorted list of all registered mnemonic handler families.
// These are family names like "ed25519", "falcon1024", not versioned key types.
func GetRegisteredFamilies() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	families := make([]string, 0, len(registry.handlers))
	for family := range registry.handlers {
		families = append(families, family)
	}
	sort.Strings(families) // Consistent ordering
	return families
}
