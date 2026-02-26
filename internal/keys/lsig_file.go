// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keys

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/util"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
)

// LSigFile represents the on-disk format for a generic LogicSig file.
// Files are encrypted using AES-256-GCM to prevent tampering (e.g., swapping recipient addresses).
// All key types (DSA and LogicSig) use the unified .key extension.
type LSigFile struct {
	FormatVersion int               `json:"format_version"` // Key file format version
	Category      string            `json:"category"`       // Always "generic_lsig" for this file type
	Address       string            `json:"address"`
	KeyType       string            `json:"key_type"`              // e.g., "timelock-v1"
	Template      string            `json:"template,omitempty"`    // Template name (e.g., "timelock")
	Parameters    map[string]string `json:"parameters,omitempty"`  // Template parameters
	BytecodeHex   string            `json:"bytecode_hex"`          // Hex-encoded TEAL bytecode
	TEALSource    string            `json:"teal_source,omitempty"` // Original TEAL source (for documentation)
	CreatedAt     string            `json:"created_at,omitempty"`  // RFC 3339 creation timestamp
}

// WriteLSigFile writes an encrypted LogicSig file to disk.
// Uses master key encryption (AES-256-GCM) to prevent tampering.
// identityID scopes the key to a specific identity directory.
// masterKey should be the derived encryption key from the keystore (not raw passphrase).
// tealSource is the original TEAL source code for documentation purposes.
func WriteLSigFile(identityID, address, keyType, template string, parameters map[string]string, bytecode []byte, tealSource string, masterKey []byte) error {
	lsigFile := LSigFile{
		FormatVersion: utilkeys.CurrentKeyFormatVersion,
		Category:      utilkeys.CategoryGenericLsig,
		Address:       address,
		KeyType:       keyType,
		Template:      template,
		Parameters:    parameters,
		BytecodeHex:   hex.EncodeToString(bytecode),
		TEALSource:    tealSource,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	// Marshal to JSON
	plaintext, err := json.MarshalIndent(lsigFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal lsig file: %w", err)
	}

	// Encrypt with master key
	encrypted, err := crypto.EncryptWithMasterKey(plaintext, masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt lsig file: %w", err)
	}

	// Ensure identity-scoped directory exists
	if err := os.MkdirAll(utilkeys.KeysDir(identityID), 0770); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	filePath := utilkeys.KeyFilePath(identityID, address)

	// Write with group-accessible permissions
	if err := os.WriteFile(filePath, encrypted, 0660); err != nil {
		return fmt.Errorf("failed to write lsig file: %w", err)
	}

	return nil
}

// ToLSigConfig converts an LSigFile to an LSigConfig for use in the cache.
func (lf *LSigFile) ToLSigConfig() (*util.LSigConfig, error) {
	bytecode, err := hex.DecodeString(lf.BytecodeHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode bytecode: %w", err)
	}

	return &util.LSigConfig{
		Category:   lf.Category,
		Address:    lf.Address,
		KeyType:    lf.KeyType,
		Template:   lf.Template,
		Parameters: lf.Parameters,
		Bytecode:   bytecode,
	}, nil
}

// IsGenericLSigType checks if a key type is a generic LogicSig (not DSA-based).
// This delegates to the genericlsig registry for proper self-registration support.
func IsGenericLSigType(keyType string) bool {
	return genericlsig.IsGenericLSigType(keyType)
}
