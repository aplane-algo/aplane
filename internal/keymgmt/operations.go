// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keymgmt

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
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
	// with fewer segments first (e.g., aplane.falcon1024.v1 before aplane.falcon1024-timelock.v1).
	sort.Slice(types, func(i, j int) bool {
		li := logicsigdsa.IsLogicSigType(types[i])
		lj := logicsigdsa.IsLogicSigType(types[j])
		if li != lj {
			return !li // standard types first
		}
		fi := logicsigdsa.RoutingFamily(types[i])
		fj := logicsigdsa.RoutingFamily(types[j])
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
	params, resolveErr = sentryrefs.ResolveCreationParams(paths, identityID, keyType, params)
	if resolveErr != nil {
		return nil, fmt.Errorf("%w: sentry reference resolution failed: %v", keygen.ErrInvalidParams, resolveErr)
	}
	if err := validateKnownWitnessRoleExclusivity(paths, identityID, keyType, params, masterKey); err != nil {
		return nil, fmt.Errorf("%w: %v", keygen.ErrInvalidParams, err)
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
	if witness.IsKeyType(genResult.KeyType) {
		spending := false
		result.IsWitnessKey = true
		result.IsSpendingAccount = &spending
	}
	return result, nil
}

func validateKnownWitnessRoleExclusivity(paths storepaths.Paths, identityID, keyType string, params map[string]string, masterKey []byte) error {
	if adminPublicKeyHex := strings.ToLower(strings.TrimSpace(params[boundedmeta.AdminPublicKeyParameter])); adminPublicKeyHex != "" {
		if _, err := boundedmeta.ParseAdminPublicKey(adminPublicKeyHex); err != nil {
			return nil // The provider owns the detailed parameter error.
		}
		references, err := sentryrefs.List(paths, identityID)
		if err != nil {
			return fmt.Errorf("check sentry witness references: %w", err)
		}
		scanned, err := keys.ScanKeysDirectoryWithMasterKey(paths, identityID, masterKey)
		if err != nil {
			return fmt.Errorf("check local sentry witness keys: %w", err)
		}
		if err := rejectAdminWitnessKnownAsSentry(adminPublicKeyHex, references, scanned); err != nil {
			return err
		}
	}

	if !keytypes.IsGuardedAccountKeyType(keyType) {
		return nil
	}
	sentryPublicKeyHex := strings.ToLower(strings.TrimSpace(params[keytypes.ParameterSentryPublicKey]))
	if sentryPublicKeyHex == "" {
		return nil // The guarded provider reports the missing required parameter.
	}
	publicKey, err := hex.DecodeString(sentryPublicKeyHex)
	if err != nil {
		return nil // The guarded provider owns the detailed parameter error.
	}
	sentryWitnessID, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		return nil // The guarded provider owns the detailed parameter error.
	}
	scanned, err := keys.ScanKeysDirectoryWithMasterKey(paths, identityID, masterKey)
	if err != nil {
		return fmt.Errorf("check existing contract-admin enrollments: %w", err)
	}
	return rejectSentryWitnessKnownAsAdmin(sentryPublicKeyHex, sentryWitnessID, scanned)
}

func rejectAdminWitnessKnownAsSentry(adminPublicKeyHex string, references []sentryrefs.Record, scanned map[string]keys.KeyScanInfo) error {
	for _, reference := range references {
		if strings.EqualFold(reference.PublicKeyHex, adminPublicKeyHex) {
			return fmt.Errorf("witness key %s is already known in the sentry role and cannot be enrolled as a contract admin", reference.ComponentKey)
		}
	}
	for witnessKeyID, info := range scanned {
		if witness.IsKeyType(info.KeyType) && strings.EqualFold(info.PublicKeyHex, adminPublicKeyHex) {
			return fmt.Errorf("witness key %s is already stored in sentry custody and cannot be enrolled as a contract admin", witnessKeyID)
		}
	}
	return nil
}

func rejectSentryWitnessKnownAsAdmin(sentryPublicKeyHex, sentryWitnessID string, scanned map[string]keys.KeyScanInfo) error {
	for _, info := range scanned {
		metadata := info.BoundedAuthorization
		if metadata != nil && strings.EqualFold(metadata.AdminPublicKeyHex, sentryPublicKeyHex) {
			return fmt.Errorf("witness key %s is already enrolled as a contract admin and cannot be enrolled as a sentry", sentryWitnessID)
		}
	}
	return nil
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

	basename := filepath.Base(keyFile)
	selector, _, ok := keys.ParseManagedCredentialFilename(basename)
	if !ok {
		return nil, fmt.Errorf("refusing to delete unrecognized managed credential filename %q", basename)
	}
	if selector != address {
		return nil, fmt.Errorf("refusing to delete managed credential %q for selector %q", basename, address)
	}
	destPath := filepath.Join(deletedKeysDir, basename)
	if err := os.Rename(keyFile, destPath); err != nil {
		return nil, fmt.Errorf("failed to move key file: %w", err)
	}
	// The removal and the tombstone must both survive a crash: a deletion
	// that resurrects after power loss is an active credential the operator
	// believes is gone.
	if err := fsutil.SyncDir(filepath.Dir(keyFile)); err != nil {
		return nil, fmt.Errorf("failed to sync keys directory after delete: %w", err)
	}
	if err := fsutil.SyncDir(deletedKeysDir); err != nil {
		return nil, fmt.Errorf("failed to sync deleted keys directory: %w", err)
	}

	return &DeleteResult{
		DeletedPath: destPath,
	}, nil
}

// KeyFileInfo contains info extracted from a key file
type KeyFileInfo struct {
	Type                string            // Full versioned type: "aplane.falcon1024.v1", "ed25519", "aplane.htlc.v1"
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
	payload, err := keys.ParsePayload(data)
	if err != nil {
		return nil, err
	}
	defer payload.ZeroSecrets()
	meta := payload.Metadata()
	return &KeyFileInfo{
		Type:                meta.KeyType,
		PublicKeyHex:        meta.PublicKeyHex,
		Parameters:          meta.Parameters,
		TemplateFingerprint: meta.TemplateFingerprint,
	}, nil
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
	payload, err := keys.ParsePayload(data)
	if err != nil {
		return "", err
	}
	defer payload.ZeroSecrets()
	return payload.TEALSource, nil
}
