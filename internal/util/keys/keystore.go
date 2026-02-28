// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keys

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
)

// keystorePath holds the configured keystore directory
var (
	keystorePath = "" // no default - must be explicitly configured
	keystoreMu   sync.RWMutex
)

// SetKeystorePath sets the keystore directory path
// This should be called once at startup before any key operations
func SetKeystorePath(path string) {
	keystoreMu.Lock()
	defer keystoreMu.Unlock()
	if path != "" {
		keystorePath = path
	}
}

// KeystorePath returns the current keystore root directory path
func KeystorePath() string {
	keystoreMu.RLock()
	defer keystoreMu.RUnlock()
	return keystorePath
}

// validatePathComponent panics if s is empty or contains path separators or traversal sequences.
// This is a programming-error guard: identity IDs used in path construction must be
// simple names (e.g., "default"), never user-controlled unsanitized strings.
func validatePathComponent(label, s string) {
	if s == "" || strings.ContainsAny(s, `/\`) || strings.Contains(s, "..") {
		panic(fmt.Sprintf("invalid %s: %q", label, s))
	}
}

// UserDir returns the identity-scoped user directory path (users/<identityID>/).
// This is the parent of per-identity subdirectories (keys/, templates/, .keystore, aplane.token).
// Panics if identityID contains path separators or traversal sequences.
func UserDir(identityID string) string {
	validatePathComponent("identity ID", identityID)
	return filepath.Join(KeystorePath(), "users", identityID)
}

// KeysDir returns the keys subdirectory for an identity (users/<identityID>/keys/).
// The identityID parameter scopes keys to a specific identity (e.g., "default").
// Panics if identityID contains path separators or traversal sequences.
func KeysDir(identityID string) string {
	return filepath.Join(UserDir(identityID), "keys")
}

// TemplatesRootDir returns the root templates directory for an identity (users/<identityID>/templates/).
// This is the parent of all template type subdirectories.
// Panics if identityID contains path separators or traversal sequences.
func TemplatesRootDir(identityID string) string {
	return filepath.Join(UserDir(identityID), "templates")
}

// TemplatesDir returns the generic templates subdirectory for an identity (users/<identityID>/templates/generic/).
// Used for generic LogicSig templates (multitemplate).
// Panics if identityID contains path separators or traversal sequences.
func TemplatesDir(identityID string) string {
	return filepath.Join(UserDir(identityID), "templates", "generic")
}

// FalconTemplatesDir returns the falcon templates subdirectory for an identity (users/<identityID>/templates/falcon/).
// Used for Falcon-1024 DSA composition templates (falcon1024template).
// Panics if identityID contains path separators or traversal sequences.
func FalconTemplatesDir(identityID string) string {
	return filepath.Join(UserDir(identityID), "templates", "falcon")
}

// KeystoreMetadataDir returns the directory where .keystore metadata lives for an identity.
// This is the same as UserDir — .keystore is stored at users/<identityID>/.keystore.
// Panics if identityID contains path separators or traversal sequences.
func KeystoreMetadataDir(identityID string) string {
	return UserDir(identityID)
}

// KeyFilePath returns the full path for a key file given an identity and address.
// All key types (Ed25519, Falcon-1024, LogicSigs) use the unified .key extension.
// Example: KeyFilePath("default", "ABC123") -> "users/default/keys/ABC123.key"
func KeyFilePath(identityID, address string) string {
	return filepath.Join(KeysDir(identityID), address+".key")
}

// SaveKeyFile saves a KeyPair to disk with master key encryption.
// This is the canonical function for persisting key files.
// identityID scopes the key to a specific identity directory.
// masterKey should be the derived master key from the keystore (not passphrase).
// Returns the ImportKeyResult with file paths.
func SaveKeyFile(keyPair *KeyPair, identityID, address string, masterKey []byte) (*ImportKeyResult, error) {
	// Ensure format version is set
	if keyPair.FormatVersion == 0 {
		keyPair.FormatVersion = CurrentKeyFormatVersion
	}

	// Set creation timestamp if not already set
	if keyPair.CreatedAt == "" {
		keyPair.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}

	// Marshal the key pair
	keyJSON, err := json.MarshalIndent(keyPair, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	defer crypto.ZeroBytes(keyJSON) // Zero JSON containing private key after use

	// Encrypt with master key
	dataToWrite := keyJSON
	if len(masterKey) > 0 {
		encrypted, err := crypto.EncryptWithMasterKey(keyJSON, masterKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt key: %w", err)
		}
		dataToWrite = encrypted
	}

	// Create identity-scoped keys subdirectory if it doesn't exist
	if err := fsutil.MkdirAll(KeysDir(identityID)); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Write private key file
	privFile := KeyFilePath(identityID, address)
	if err := fsutil.WriteFile(privFile, dataToWrite); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}

	return &ImportKeyResult{
		Address:     address,
		PrivateFile: privFile,
		LsigFile:    "",
		PublicFile:  "",
	}, nil
}
