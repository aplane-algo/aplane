// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keymgmt

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/sentry/attrefs"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// GetValidKeyTypes returns all valid key types that can be generated.
// This returns versioned types (e.g., "aplane.falcon1024.v1") not family names.
func GetValidKeyTypes() []string {
	return GetValidKeyTypesWithActivated(nil)
}

// GetValidKeyTypesWithActivated returns default-enabled key types plus
// identity-activated library-visible compiled key types.
func GetValidKeyTypesWithActivated(activated []string) []string {
	activatedSet := activatedKeyTypeSet(activated)
	seen := make(map[string]bool)
	var types []string

	// Add non-LogicSig types from algorithm registry (e.g., "ed25519")
	// For these types, family name == key type (no versioning)
	for _, family := range algorithm.GetRegisteredFamilies() {
		meta, err := algorithm.GetMetadata(family)
		if err == nil && !meta.RequiresLogicSig() && keyTypeEnabledForGeneration(family, activatedSet) {
			types = appendKeyType(types, seen, family)
		}
	}

	// Add versioned LogicSig DSA types (e.g., "aplane.falcon1024.v1")
	for _, keyType := range logicsigdsa.GetKeyTypes() {
		if keyTypeEnabledForGeneration(keyType, activatedSet) {
			types = appendKeyType(types, seen, keyType)
		}
	}

	for _, entry := range keytypecatalog.DefaultEnabled() {
		types = appendKeyType(types, seen, entry.KeyType)
	}

	// Sort: standard algorithms first, then LogicSig DSAs grouped by family
	// with fewer segments first (e.g., aplane.falcon1024.v1 before aplane.falcon1024-hashlock.v1).
	sort.Slice(types, func(i, j int) bool {
		li := logicsigdsa.IsLogicSigType(types[i])
		lj := logicsigdsa.IsLogicSigType(types[j])
		if li != lj {
			return !li // standard types first
		}
		fi := logicsigdsa.GetFamily(types[i])
		fj := logicsigdsa.GetFamily(types[j])
		if fi != fj {
			return fi < fj
		}
		si := strings.Count(types[i], "-")
		sj := strings.Count(types[j], "-")
		if si != sj {
			return si < sj
		}
		return types[i] < types[j]
	})

	return types
}

func appendKeyType(types []string, seen map[string]bool, keyType string) []string {
	keyType = strings.ToLower(strings.TrimSpace(keyType))
	if keyType == "" || seen[keyType] {
		return types
	}
	seen[keyType] = true
	return append(types, keyType)
}

// GetValidKeyTypesForIdentity returns default-enabled key types plus
// identity-enabled opt-in compiled providers. Provider registries are
// process-global; the enabled state records on disk are the identity boundary.
func GetValidKeyTypesForIdentity(paths storepaths.Paths, identityID string) ([]string, error) {
	enabled, err := keytypestate.ListEnabled(paths, identityID)
	if err != nil {
		return nil, err
	}
	return GetValidKeyTypesWithActivated(enabled), nil
}

// IsValidKeyType checks if a key type is valid by querying the registry.
func IsValidKeyType(keyType string) bool {
	return IsValidKeyTypeWithActivated(keyType, nil)
}

func IsValidKeyTypeWithActivated(keyType string, activated []string) bool {
	return isKeyTypeInList(keyType, GetValidKeyTypesWithActivated(activated))
}

// SupportsMnemonicImport reports whether user-entered mnemonic import is
// enabled for a key type. This is intentionally narrower than "has mnemonic
// material"; only externally recoverable wallet/tool protocols should return
// true.
func SupportsMnemonicImport(keyType string) bool {
	keyType = strings.ToLower(strings.TrimSpace(keyType))
	if keyType == "" {
		return false
	}

	if provider := lsigprovider.Get(keyType); provider != nil {
		mnemonicProvider, ok := provider.(lsigprovider.MnemonicProvider)
		return ok && mnemonicProvider.SupportsMnemonicImport()
	}

	meta, err := algorithm.GetMetadata(keyType)
	if err != nil || meta == nil {
		return false
	}
	return !meta.RequiresLogicSig() && meta.SupportsMnemonicImport()
}

func GetMnemonicImportKeyTypesWithActivated(activated []string) []string {
	validTypes := GetValidKeyTypesWithActivated(activated)
	importTypes := make([]string, 0, len(validTypes))
	for _, keyType := range validTypes {
		if SupportsMnemonicImport(keyType) {
			importTypes = append(importTypes, keyType)
		}
	}
	return importTypes
}

func activatedKeyTypeSet(activated []string) map[string]bool {
	set := make(map[string]bool, len(activated))
	for _, keyType := range activated {
		keyType = strings.ToLower(strings.TrimSpace(keyType))
		if keyType != "" {
			set[keyType] = true
		}
	}
	return set
}

func keyTypeEnabledForGeneration(keyType string, activated map[string]bool) bool {
	if keytypecatalog.IsDefaultEnabled(keyType) {
		return true
	}
	return activated[strings.ToLower(strings.TrimSpace(keyType))]
}

// GenerateKey creates a new random key with mnemonic backup.
// keyType must be explicitly specified (e.g., "ed25519", "aplane.falcon1024.v1").
// masterKey is the derived encryption key from the keystore (not raw passphrase).
func GenerateKey(paths storepaths.Paths, identityID string, keyType string, masterKey []byte, params map[string]string) (*GenerateResult, error) {
	return GenerateKeyWithActivatedContext(context.Background(), paths, identityID, keyType, masterKey, params, nil)
}

func GenerateKeyWithActivatedContext(ctx context.Context, paths storepaths.Paths, identityID string, keyType string, masterKey []byte, params map[string]string, activated []string) (*GenerateResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	validTypes := GetValidKeyTypesWithActivated(activated)
	if keyType == "" {
		return nil, fmt.Errorf("key type must be specified (one of: %s)", strings.Join(validTypes, ", "))
	}

	if !isKeyTypeInList(keyType, validTypes) {
		return nil, fmt.Errorf("invalid key type: %s (must be one of: %s)", keyType, strings.Join(validTypes, ", "))
	}
	var resolveErr error
	params, resolveErr = attrefs.ResolveCreationParams(paths, identityID, keyType, params)
	if resolveErr != nil {
		return nil, fmt.Errorf("%w: sentry reference resolution failed: %v", keygen.ErrInvalidParams, resolveErr)
	}

	generator, err := keygen.GetGenerator(keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to get generator: %w", err)
	}

	genResult, err := generator.GenerateRandom(ctx, paths, identityID, masterKey, keyType, params)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	result := &GenerateResult{
		Address:      genResult.Address,
		PublicKeyHex: genResult.PublicKeyHex,
		KeyType:      genResult.KeyType, // Full versioned type from generator
		Mnemonic:     genResult.Mnemonic,
		KeyFile:      genResult.KeyFiles.PrivateFile,
	}
	if keytypes.IsAttestorComponentKeyType(genResult.KeyType) {
		spending := false
		result.IsComponentKey = true
		result.IsSpendingAccount = &spending
	}
	return result, nil
}

// ImportKey imports a key from a mnemonic phrase.
// masterKey is the derived encryption key from the keystore (not raw passphrase).
func ImportKey(paths storepaths.Paths, identityID string, keyType string, mnemonicStr string, masterKey []byte, params map[string]string) (*ImportResult, error) {
	return ImportKeyWithActivatedContext(context.Background(), paths, identityID, keyType, mnemonicStr, masterKey, params, nil)
}

func ImportKeyWithActivatedContext(ctx context.Context, paths storepaths.Paths, identityID string, keyType string, mnemonicStr string, masterKey []byte, params map[string]string, activated []string) (*ImportResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	validTypes := GetValidKeyTypesWithActivated(activated)
	if !isKeyTypeInList(keyType, validTypes) {
		return nil, fmt.Errorf("invalid key type: %s (must be one of: %s)", keyType, strings.Join(validTypes, ", "))
	}
	if !SupportsMnemonicImport(keyType) {
		importTypes := GetMnemonicImportKeyTypesWithActivated(activated)
		return nil, fmt.Errorf("mnemonic import not supported for key type: %s (must be one of: %s)", keyType, strings.Join(importTypes, ", "))
	}

	generator, err := keygen.GetGenerator(keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to get generator: %w", err)
	}

	genResult, err := generator.GenerateFromMnemonic(ctx, paths, identityID, mnemonicStr, masterKey, keyType, params)
	if err != nil {
		return nil, fmt.Errorf("failed to import key: %w", err)
	}

	return &ImportResult{
		Address: genResult.Address,
		KeyType: keyType,
		KeyFile: genResult.KeyFiles.PrivateFile,
	}, nil
}

func isKeyTypeInList(keyType string, validTypes []string) bool {
	for _, valid := range validTypes {
		if keyType == valid {
			return true
		}
	}
	return false
}

// DeleteKey moves a key file to the identity-local deleted/keys directory.
func DeleteKey(address, keyFile, deletedKeysDir string) (*DeleteResult, error) {
	if err := fsutil.MkdirAll(deletedKeysDir); err != nil {
		return nil, fmt.Errorf("failed to create deleted keys directory: %w", err)
	}

	destPath := filepath.Join(deletedKeysDir, fmt.Sprintf("%s.key", address))
	if err := os.Rename(keyFile, destPath); err != nil {
		return nil, fmt.Errorf("failed to move key file: %w", err)
	}

	return &DeleteResult{
		DeletedPath: destPath,
	}, nil
}

// KeyFileInfo contains info extracted from a key file
type KeyFileInfo struct {
	Type                string            // Full versioned type: "aplane.falcon1024.v1", "ed25519", "aplane.timed-whitelist.v1"
	PublicKeyHex        string            // Hex-encoded public key stored in the key payload.
	Parameters          map[string]string // Parameters for LogicSig keys (nil for DSA keys)
	TemplateFingerprint string
}

// DetectKeyInfoFromFileWithMasterKey reads a key file and returns type and parameters.
// Uses master key for decryption (envelope_version 2).
func DetectKeyInfoFromFileWithMasterKey(keyFile string, masterKey []byte) (*KeyFileInfo, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(data)

	if !crypto.IsEncrypted(data) {
		return nil, fmt.Errorf("key file must be encrypted")
	}
	decrypted, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(decrypted)

	return parseKeyFileInfo(decrypted)
}

// parseKeyFileInfo parses decrypted key file data and extracts type and parameters.
func parseKeyFileInfo(data []byte) (*KeyFileInfo, error) {
	keyData, err := keys.ParseKeyPayloadMetadata(data)
	if err != nil {
		return nil, err
	}

	if keyData.KeyType != "" {
		return &KeyFileInfo{
			Type:                keyData.KeyType,
			PublicKeyHex:        keyData.PublicKeyHex,
			Parameters:          keyData.Parameters,
			TemplateFingerprint: keyData.TemplateFingerprint,
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
	defer crypto.ZeroBytes(data)

	if !crypto.IsEncrypted(data) {
		return "", fmt.Errorf("key file must be encrypted")
	}
	decrypted, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(decrypted)

	return parseDisplayTEAL(decrypted)
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
