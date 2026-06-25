// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Generator defines the interface for key generation.
// All methods require an explicit keyType parameter - the system never
// implicitly chooses a key type for the user.
// masterKey is the derived encryption key from the keystore (not raw passphrase).
type Generator interface {
	// RoutingFamily returns the algorithm family this generator supports (e.g., "falcon1024", "ed25519")
	RoutingFamily() string

	// GenerateFromSeed generates a key from a deterministic seed.
	// keyType must be explicitly specified (e.g., "aplane.falcon1024.v1", "ed25519").
	GenerateFromSeed(ctx context.Context, paths storepaths.Paths, identityID string, seed []byte, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error)

	// GenerateFromMnemonic generates a key from mnemonic words.
	// keyType must be explicitly specified (e.g., "aplane.falcon1024.v1", "ed25519").
	GenerateFromMnemonic(ctx context.Context, paths storepaths.Paths, identityID string, mnemonic string, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error)

	// GenerateRandom generates a new random key.
	// keyType must be explicitly specified (e.g., "aplane.falcon1024.v1", "ed25519").
	GenerateRandom(ctx context.Context, paths storepaths.Paths, identityID string, masterKey []byte, keyType string, params map[string]string) (*GenerationResult, error)
}

// ErrInvalidParams marks key-generation failures caused by invalid
// user-supplied creation parameters.
var ErrInvalidParams = errors.New("invalid key generation parameters")

// GenerationResult contains the result of key generation
type GenerationResult struct {
	Address      string
	KeyType      string // Full versioned type: "aplane.falcon1024.v1" or "ed25519"
	PublicKeyHex string
	Mnemonic     string // Recovery mnemonic
	KeyFiles     *keys.ImportKeyResult
}

// GeneratorRegistry manages key generators for different key types
type GeneratorRegistry struct {
	mu         sync.RWMutex
	generators map[string]Generator
}

// Global registry instance
var registry = &GeneratorRegistry{
	generators: make(map[string]Generator),
}

// Register registers a key generator for an algorithm family.
// Duplicate family registrations are a programmer error and panic.
func Register(generator Generator) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	family := generator.RoutingFamily()
	if _, exists := registry.generators[family]; exists {
		panic(fmt.Sprintf("key generator already registered for family %q", family))
	}
	registry.generators[family] = generator
}

// GetGenerator retrieves a key generator by key type.
// Versioned types like "aplane.falcon1024.v1" are normalized to their family type.
func GetGenerator(keyType string) (Generator, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	// Try direct lookup first
	if generator, exists := registry.generators[keyType]; exists {
		return generator, nil
	}

	if keytypes.IsSentryKeyType(keyType) {
		return nil, fmt.Errorf("no exact key generator registered for key type: %s", keyType)
	}

	// Try family name (e.g., "aplane.falcon1024.v1" -> "falcon1024")
	family := logicsigdsa.RoutingFamily(keyType)
	if family != keyType {
		if generator, exists := registry.generators[family]; exists {
			return generator, nil
		}
	}

	return nil, fmt.Errorf("no key generator registered for key type: %s", keyType)
}

// GetRegisteredFamilies returns a sorted list of all registered key generator families.
// These are family names like "ed25519", "falcon1024", not versioned key types.
func GetRegisteredFamilies() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	families := make([]string, 0, len(registry.generators))
	for family := range registry.generators {
		families = append(families, family)
	}
	sort.Strings(families) // Consistent ordering
	return families
}
