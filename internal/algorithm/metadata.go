// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package algorithm provides signature algorithm metadata registry.
//
// This registry stores metadata (signature sizes, mnemonic word counts,
// display colors, etc.) for all signature algorithms. Both Ed25519 and
// Falcon register their metadata here.
//
// For LogicSig-based post-quantum DSAs, internal/logicsigdsa provides
// additional versioned operations (keypair generation, LogicSig derivation).
// The two registries are complementary - this one for metadata, logicsigdsa
// for crypto operations.
package algorithm

import (
	"fmt"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/util"
)

// SignatureMetadata provides metadata about a signature algorithm
type SignatureMetadata interface {
	// Family returns the algorithm family name (e.g., "falcon1024", "ed25519")
	// This is distinct from LogicSigDSA.KeyType() which returns versioned types like "falcon1024-v1"
	Family() string

	// CryptoSignatureSize returns the maximum cryptographic signature size in bytes
	CryptoSignatureSize() int

	// MnemonicWordCount returns the number of words in the mnemonic phrase
	MnemonicWordCount() int

	// MnemonicScheme returns the mnemonic scheme used (e.g., "bip39", "algorand")
	MnemonicScheme() string

	// RequiresLogicSig returns true if this key type requires LogicSig derivation
	RequiresLogicSig() bool

	// CurrentLsigVersion returns the current LogicSig derivation version for new keys.
	// Returns 0 if this key type doesn't require LogicSig (e.g., ed25519).
	CurrentLsigVersion() int

	// SupportedLsigVersions returns all supported LogicSig derivation versions.
	// Used for mnemonic recovery to try all possible versions.
	// Returns nil/empty if this key type doesn't require LogicSig.
	SupportedLsigVersions() []int

	// DefaultDerivation returns the default key derivation method
	DefaultDerivation() string

	// DisplayColor returns the ANSI color code for displaying addresses of this type
	// Returns empty string for no color (e.g., "33" for yellow, "36" for cyan)
	DisplayColor() string
}

// basicMetadata is a simple implementation of SignatureMetadata
type basicMetadata struct {
	family                string
	signatureSize         int
	mnemonicWordCount     int
	mnemonicScheme        string
	requiresLogicSig      bool
	currentLsigVersion    int
	supportedLsigVersions []int
	defaultDerivation     string
	displayColor          string
}

func (m *basicMetadata) Family() string               { return m.family }
func (m *basicMetadata) CryptoSignatureSize() int     { return m.signatureSize }
func (m *basicMetadata) MnemonicWordCount() int       { return m.mnemonicWordCount }
func (m *basicMetadata) MnemonicScheme() string       { return m.mnemonicScheme }
func (m *basicMetadata) RequiresLogicSig() bool       { return m.requiresLogicSig }
func (m *basicMetadata) CurrentLsigVersion() int      { return m.currentLsigVersion }
func (m *basicMetadata) SupportedLsigVersions() []int { return m.supportedLsigVersions }
func (m *basicMetadata) DefaultDerivation() string    { return m.defaultDerivation }
func (m *basicMetadata) DisplayColor() string         { return m.displayColor }

// Global registry instance
var metadataRegistry = util.NewStringRegistry[SignatureMetadata]()

// RegisterMetadata registers metadata for a signature algorithm family
// This is idempotent - duplicate registrations are silently ignored
func RegisterMetadata(metadata SignatureMetadata) {
	metadataRegistry.Set(metadata.Family(), metadata)
}

// GetMetadata retrieves metadata for a key type.
// Versioned types like "falcon1024-v1" are normalized to their family type.
// For unregistered providers (e.g., keystore templates not loaded locally),
// falls back to prefix matching against registered families.
func GetMetadata(keyType string) (SignatureMetadata, error) {
	// Try direct lookup first
	if metadata, ok := metadataRegistry.Get(keyType); ok {
		return metadata, nil
	}

	// Try family name via provider registry (e.g., "falcon1024-v1" -> "falcon1024")
	family := logicsigdsa.GetFamily(keyType)
	if family != keyType {
		if metadata, ok := metadataRegistry.Get(family); ok {
			return metadata, nil
		}
	}

	// Fallback: prefix match against registered families.
	// This handles keystore template types (e.g., "falcon1024-hashlock-v2")
	// that aren't registered locally but belong to a known family ("falcon1024").
	for _, registeredFamily := range metadataRegistry.Keys() {
		if strings.HasPrefix(keyType, registeredFamily+"-") {
			if metadata, ok := metadataRegistry.Get(registeredFamily); ok {
				return metadata, nil
			}
		}
	}

	return nil, fmt.Errorf("no metadata registered for key type: %s", keyType)
}

// GetDisplayColor returns the ANSI color code for a key type
// Returns empty string if no color is defined or key type is unknown
func GetDisplayColor(keyType string) string {
	metadata, err := GetMetadata(keyType)
	if err != nil {
		return ""
	}
	return metadata.DisplayColor()
}

// GetRegisteredFamilies returns a sorted list of all registered algorithm families.
// These are family names like "ed25519", "falcon1024", not versioned key types.
func GetRegisteredFamilies() []string {
	return metadataRegistry.Keys()
}

var registerEd25519MetadataOnce sync.Once

// RegisterEd25519Metadata registers Ed25519 metadata with the algorithm registry.
// This is idempotent and safe to call multiple times.
func RegisterEd25519Metadata() {
	registerEd25519MetadataOnce.Do(func() {
		RegisterMetadata(&basicMetadata{
			family:                "ed25519",
			signatureSize:         64,
			mnemonicWordCount:     25,
			mnemonicScheme:        "algorand",
			requiresLogicSig:      false,
			currentLsigVersion:    0,   // No LSig needed
			supportedLsigVersions: nil, // No LSig needed
			defaultDerivation:     "algorand-standard",
			displayColor:          "36", // Cyan for ed25519
		})
	})
}
