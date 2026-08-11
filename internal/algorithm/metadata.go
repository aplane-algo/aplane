// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package algorithm provides signature algorithm metadata registry.
//
// This registry stores metadata (signature sizes, mnemonic word counts,
// display colors, etc.) for all signature algorithms. Both Ed25519 and
// Falcon register their metadata here.
//
// For LogicSig-based DSAs, internal/logicsigdsa provides
// additional versioned operations (keypair generation, LogicSig derivation).
// The two registries are complementary - this one for metadata, logicsigdsa
// for crypto operations.
package algorithm

import (
	"fmt"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/xregistry"
)

// SignatureMetadata provides metadata about a signature algorithm
type SignatureMetadata interface {
	// RoutingFamily returns the algorithm family name (e.g., "falcon1024", "ed25519")
	// This is distinct from LogicSigDSA.KeyType() which returns versioned types like "aplane.falcon1024.v1"
	RoutingFamily() string

	// CryptoSignatureSize returns the maximum cryptographic signature size in bytes
	CryptoSignatureSize() int

	// MnemonicWordCount returns the number of words in the mnemonic phrase
	MnemonicWordCount() int

	// SupportsMnemonicImport returns true when user-entered mnemonic import is
	// supported for this key type.
	SupportsMnemonicImport() bool

	// MnemonicScheme returns the mnemonic scheme used (e.g., "bip39", "algorand")
	MnemonicScheme() string

	// AuthorizationKind returns the consensus authorization shape produced by
	// this key family. It is authoritative for display and fee/signing logic;
	// RequiresLogicSig remains for compatibility with older projections.
	AuthorizationKind() AuthorizationKind

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

// AuthorizationKind is the closed set of account-authorization envelopes
// understood by APlane.
type AuthorizationKind string

const (
	AuthorizationEd25519  AuthorizationKind = "ed25519"
	AuthorizationNativePQ AuthorizationKind = "native_pq"
	AuthorizationLogicSig AuthorizationKind = "logic_sig"
)

// basicMetadata is a simple implementation of SignatureMetadata
type basicMetadata struct {
	family                 string
	signatureSize          int
	mnemonicWordCount      int
	supportsMnemonicImport bool
	mnemonicScheme         string
	authorizationKind      AuthorizationKind
	requiresLogicSig       bool
	currentLsigVersion     int
	supportedLsigVersions  []int
	defaultDerivation      string
	displayColor           string
}

func (m *basicMetadata) RoutingFamily() string                { return m.family }
func (m *basicMetadata) CryptoSignatureSize() int             { return m.signatureSize }
func (m *basicMetadata) MnemonicWordCount() int               { return m.mnemonicWordCount }
func (m *basicMetadata) SupportsMnemonicImport() bool         { return m.supportsMnemonicImport }
func (m *basicMetadata) MnemonicScheme() string               { return m.mnemonicScheme }
func (m *basicMetadata) AuthorizationKind() AuthorizationKind { return m.authorizationKind }
func (m *basicMetadata) RequiresLogicSig() bool               { return m.requiresLogicSig }
func (m *basicMetadata) CurrentLsigVersion() int              { return m.currentLsigVersion }
func (m *basicMetadata) SupportedLsigVersions() []int         { return m.supportedLsigVersions }
func (m *basicMetadata) DefaultDerivation() string            { return m.defaultDerivation }
func (m *basicMetadata) DisplayColor() string                 { return m.displayColor }

// Global registry instance
var metadataRegistry = xregistry.NewStringRegistry[SignatureMetadata]()

// RegisterMetadata registers metadata for a signature algorithm family
// This is idempotent - duplicate registrations are silently ignored
func RegisterMetadata(metadata SignatureMetadata) {
	metadataRegistry.Set(metadata.RoutingFamily(), metadata)
}

// GetMetadata retrieves metadata for a key type, resolving via the key type's
// routing family (e.g. "aplane.falcon1024.v1" -> "aplane.falcon1024"). If that
// fails it falls back to a best-effort prefix match (see hasFamilyPrefix).
//
// This rides the RESOLVE axis (docs/ARCH_KEYTYPE_AXES.md); the hasFamilyPrefix
// fallback below is a display-only best-effort, not a separate resolution
// mechanism.
func GetMetadata(keyType string) (SignatureMetadata, error) {
	if metadata, ok := logicsigdsa.ResolveByKeyType(keyType, metadataRegistry.Get); ok {
		return metadata, nil
	}

	// Best-effort fallback for an UNREGISTERED template whose routing family is
	// not resolvable from a registered provider — e.g. a keystore template not
	// loaded in this process, queried on the client side for display. The base
	// is not derivable from the key-type string alone, so this substring-matches
	// the key type against registered families ("aplane.falcon1024-timelock.v1"
	// -> the "aplane.falcon1024" family's metadata).
	//
	// This path is display-only: keygen and signing never reach it because they
	// always have a registered provider or a stored base key type in the key
	// file. Removing it cleanly would require threading that stored base through
	// the display-color callback (addressdisplay.ColorFormatter), a cross-layer
	// API change not worth it for a cosmetic fallback.
	for _, registeredFamily := range metadataRegistry.Keys() {
		if hasFamilyPrefix(keyType, registeredFamily) {
			if metadata, ok := metadataRegistry.Get(registeredFamily); ok {
				return metadata, nil
			}
		}
	}

	return nil, fmt.Errorf("no metadata registered for key type: %s", keyType)
}

func hasFamilyPrefix(keyType, family string) bool {
	keyType = strings.ToLower(strings.TrimSpace(keyType))
	family = strings.ToLower(strings.TrimSpace(family))
	if keyType == "" || family == "" {
		return false
	}
	if strings.HasPrefix(keyType, family+"-") || strings.HasPrefix(keyType, family+"_") {
		return true
	}
	return strings.Contains(keyType, "."+family+"-") || strings.Contains(keyType, "."+family+"_")
}

// DisplayLabel returns a short human-readable label for a key type's category.
func DisplayLabel(meta SignatureMetadata) string {
	switch meta.AuthorizationKind() {
	case AuthorizationLogicSig:
		return "LogicSig DSA"
	case AuthorizationNativePQ:
		return "native post-quantum"
	default:
		return "standard Algorand"
	}
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
			family:                 "ed25519",
			signatureSize:          64,
			mnemonicWordCount:      25,
			supportsMnemonicImport: true,
			mnemonicScheme:         "algorand",
			authorizationKind:      AuthorizationEd25519,
			requiresLogicSig:       false,
			currentLsigVersion:     0,   // No LSig needed
			supportedLsigVersions:  nil, // No LSig needed
			defaultDerivation:      "algorand-standard",
			displayColor:           "36", // Cyan for ed25519
		})
	})
}
