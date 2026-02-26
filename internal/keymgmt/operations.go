// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keymgmt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
)

// GetValidKeyTypes returns all valid key types that can be generated.
// This returns versioned types (e.g., "falcon1024-v1") not family names.
func GetValidKeyTypes() []string {
	var types []string

	// Add non-LogicSig types from algorithm registry (e.g., "ed25519")
	// For these types, family name == key type (no versioning)
	for _, family := range algorithm.GetRegisteredFamilies() {
		meta, err := algorithm.GetMetadata(family)
		if err == nil && !meta.RequiresLogicSig() {
			types = append(types, family)
		}
	}

	// Add versioned LogicSig DSA types (e.g., "falcon1024-v1")
	types = append(types, logicsigdsa.GetKeyTypes()...)

	return types
}

// IsValidKeyType checks if a key type is valid by querying the registry.
func IsValidKeyType(keyType string) bool {
	for _, valid := range GetValidKeyTypes() {
		if keyType == valid {
			return true
		}
	}
	return false
}

// GenerateKey creates a new random key with mnemonic backup.
// keyType must be explicitly specified (e.g., "ed25519", "falcon1024-v1").
// masterKey is the derived encryption key from the keystore (not raw passphrase).
func GenerateKey(keyType string, masterKey []byte, params map[string]string) (*GenerateResult, error) {
	if keyType == "" {
		return nil, fmt.Errorf("key type must be specified (one of: %s)", strings.Join(GetValidKeyTypes(), ", "))
	}

	if !IsValidKeyType(keyType) {
		return nil, fmt.Errorf("invalid key type: %s (must be one of: %s)", keyType, strings.Join(GetValidKeyTypes(), ", "))
	}

	generator, err := keygen.GetGenerator(keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to get generator: %w", err)
	}

	genResult, err := generator.GenerateRandom(masterKey, keyType, params)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return &GenerateResult{
		Address:  genResult.Address,
		KeyType:  genResult.KeyType, // Full versioned type from generator
		Mnemonic: genResult.Mnemonic,
		KeyFile:  genResult.KeyFiles.PrivateFile,
	}, nil
}

// ImportKey imports a key from a mnemonic phrase.
// masterKey is the derived encryption key from the keystore (not raw passphrase).
func ImportKey(keyType string, mnemonicStr string, masterKey []byte, params map[string]string) (*ImportResult, error) {
	if !IsValidKeyType(keyType) {
		return nil, fmt.Errorf("invalid key type: %s (must be one of: %s)", keyType, strings.Join(GetValidKeyTypes(), ", "))
	}

	generator, err := keygen.GetGenerator(keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to get generator: %w", err)
	}

	genResult, err := generator.GenerateFromMnemonic(mnemonicStr, masterKey, keyType, params)
	if err != nil {
		return nil, fmt.Errorf("failed to import key: %w", err)
	}

	return &ImportResult{
		Address: genResult.Address,
		KeyType: keyType,
		KeyFile: genResult.KeyFiles.PrivateFile,
	}, nil
}

// DeleteKey moves a key file to the deletedkeys directory.
// identityID is used to scope the deletedkeys path (e.g., deletedkeys/<identityID>/).
func DeleteKey(address, keyFile, keysDir, identityID string) (*DeleteResult, error) {
	// Determine the identity-scoped deleted keys directory.
	// keysDir is store/users/<identityID>/keys, so go up to store root.
	keystoreRoot := filepath.Dir(filepath.Dir(filepath.Dir(keysDir)))
	deletedDir := filepath.Join(keystoreRoot, "deletedkeys", identityID)

	// Create deletedkeys directory if it doesn't exist
	if err := fsutil.MkdirAll(deletedDir); err != nil {
		return nil, fmt.Errorf("failed to create deletedkeys directory: %w", err)
	}

	// Move key file to deletedkeys
	destPath := filepath.Join(deletedDir, fmt.Sprintf("%s.key", address))
	if err := os.Rename(keyFile, destPath); err != nil {
		return nil, fmt.Errorf("failed to move key file: %w", err)
	}

	return &DeleteResult{
		DeletedPath: destPath,
	}, nil
}

// ExportKey exports a key's mnemonic backup phrase.
// masterKey is the derived encryption key from the keystore (not raw passphrase).
func ExportKey(address string, keyFile string, masterKey []byte) (*ExportResult, error) {
	// Read key file
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Decrypt if necessary (using master key)
	if crypto.IsEncrypted(data) {
		decrypted, err := crypto.DecryptWithMasterKey(data, masterKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt key file: %w", err)
		}
		data = decrypted
	}

	// Parse key to determine type
	var keyData utilkeys.KeyPair
	if err := json.Unmarshal(data, &keyData); err != nil {
		return nil, fmt.Errorf("failed to parse key file: %w", err)
	}

	// Get base type for mnemonic handler (strip version suffix for LogicSig types)
	baseType := keyData.KeyType
	if family := logicsigdsa.GetFamily(keyData.KeyType); family != "" {
		baseType = family
	}

	// Get mnemonic handler for this key type
	handler, err := mnemonic.GetHandler(baseType)
	if err != nil {
		return nil, fmt.Errorf("unsupported key type for export: %s", keyData.KeyType)
	}

	var mnemonicStr string

	if keyData.KeyType == "ed25519" {
		// Ed25519: derive mnemonic from private key
		privBytes, err := hex.DecodeString(keyData.PrivateKeyHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key: %w", err)
		}

		// For Ed25519, reconstruct mnemonic from private key (Algorand-specific)
		privKey := privBytes[:64] // Algorand uses 64-byte private keys
		mnemonicStr, err = mnemonic.KeyToMnemonic(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to derive mnemonic: %w", err)
		}
	} else if logicsigdsa.IsLogicSigType(keyData.KeyType) {
		// LogicSig types (Falcon, etc.): check if entropy is stored
		if keyData.EntropyHex == "" {
			return nil, fmt.Errorf("cannot export mnemonic: key was generated without BIP-39 mnemonic (no entropy stored)")
		}

		// Convert entropy to mnemonic
		entropy, err := hex.DecodeString(keyData.EntropyHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode entropy: %w", err)
		}

		mnemonicStr, err = handler.EntropyToMnemonic(entropy)
		if err != nil {
			return nil, fmt.Errorf("failed to convert entropy to mnemonic: %w", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported key type: %s", keyData.KeyType)
	}

	// Collect creation parameters (needed for address re-derivation of composeDSA types)
	var params map[string]string
	if len(keyData.Params) > 0 {
		params = keyData.Params
	}

	return &ExportResult{
		Address:    address,
		KeyType:    keyData.KeyType, // Full versioned type: "falcon1024-v1" or "ed25519"
		Mnemonic:   mnemonicStr,
		WordCount:  handler.WordCount(),
		Parameters: params,
	}, nil
}

// KeyFileInfo contains info extracted from a key file
type KeyFileInfo struct {
	Type       string            // Full versioned type: "falcon1024-v1", "ed25519", "timelock-v1"
	Parameters map[string]string // Parameters for LogicSig keys (nil for DSA keys)
}

// DetectKeyInfoFromFileWithMasterKey reads a key file and returns type and parameters.
// Uses master key for decryption (envelope_version 2).
func DetectKeyInfoFromFileWithMasterKey(keyFile string, masterKey []byte) (*KeyFileInfo, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	// Decrypt if necessary
	if crypto.IsEncrypted(data) {
		decrypted, err := crypto.DecryptWithMasterKey(data, masterKey)
		if err != nil {
			return nil, err
		}
		data = decrypted
	}

	return parseKeyFileInfo(data)
}

// parseKeyFileInfo parses decrypted key file data and extracts type and parameters.
func parseKeyFileInfo(data []byte) (*KeyFileInfo, error) {
	// Parse key file - all key types now use key_type field
	// Note: Generic LogicSigs use "parameters", DSA hybrids use "params"
	var keyData struct {
		KeyType    string            `json:"key_type"`   // All keys: ed25519, falcon1024-v1, timelock-v1, etc.
		Parameters map[string]string `json:"parameters"` // Generic LogicSig parameters (optional)
		Params     map[string]string `json:"params"`     // DSA hybrid parameters (falcon1024-timelock-v1, etc.)
	}
	if err := json.Unmarshal(data, &keyData); err != nil {
		return nil, err
	}

	if keyData.KeyType != "" {
		// Use "parameters" if present, otherwise fall back to "params" (DSA hybrids)
		params := keyData.Parameters
		if len(params) == 0 && len(keyData.Params) > 0 {
			params = keyData.Params
		}
		return &KeyFileInfo{
			Type:       keyData.KeyType,
			Parameters: params,
		}, nil
	}

	return nil, fmt.Errorf("key file missing required 'key_type' field")
}

// GetDisplayTEALWithMasterKey returns the TEAL source code for generic LogicSigs.
// Uses master key for decryption (envelope_version 2).
func GetDisplayTEALWithMasterKey(keyFile string, masterKey []byte) (string, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}

	// Decrypt if necessary
	if crypto.IsEncrypted(data) {
		decrypted, err := crypto.DecryptWithMasterKey(data, masterKey)
		if err != nil {
			return "", err
		}
		data = decrypted
	}

	return parseDisplayTEAL(data)
}

// parseDisplayTEAL extracts TEAL source from decrypted key file data.
// Returns the stored TEAL source if available, empty string otherwise.
func parseDisplayTEAL(data []byte) (string, error) {
	var keyData struct {
		TEALSource string `json:"teal_source"`
	}
	if err := json.Unmarshal(data, &keyData); err != nil {
		return "", err
	}
	return keyData.TEALSource, nil
}
