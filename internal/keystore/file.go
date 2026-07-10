// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystore

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// FileKeyStore implements KeyStore using encrypted files on disk
type FileKeyStore struct {
	paths      storepaths.Paths
	keysDir    string
	identityID string // Identity used for scanning (e.g., "default")

	// Cache of address -> KeyScanInfo (populated by Scan)
	// Contains both file path and key type from single decrypt
	cache        map[string]keys.KeyScanInfo
	scanWarnings []keys.KeyScanWarning
	cacheLock    sync.RWMutex

	// Master key for envelope_version 2 decryption
	// Derived once during Scan() from keystore metadata salt
	masterKey []byte
}

// SigningSummary is the non-sensitive key-file signing metadata cached at scan time.
type SigningSummary struct {
	Category               string
	Parameters             map[string]string
	SigningArgs            []lsigprovider.RuntimeArgDef
	SigningMetadataVersion int
	TemplateFingerprint    string
}

// NewFileKeyStoreForPaths creates a new file-based key store rooted at the provided keystore paths.
func NewFileKeyStoreForPaths(paths storepaths.Paths, identityID string) *FileKeyStore {
	return &FileKeyStore{
		paths:      paths,
		keysDir:    paths.KeysDir(identityID),
		identityID: identityID,
		cache:      make(map[string]keys.KeyScanInfo),
	}
}

// InitializeMasterKey derives and stores the master key from the passphrase.
// This should be called before Scan() when you need the master key early
// (e.g., for template scanning that happens before key scanning).
// Returns the master key for external use (e.g., template scanning).
// Caller should NOT zero the returned key - it's owned by FileKeyStore, and
// a concurrent lock (identity.Runtime.performLock under passphraseLock)
// zeroes it via ClearMasterKey. The returned slice is therefore only valid
// while the caller holds whatever lock serializes it against locking - in
// the daemon that is identity.Runtime's passphraseLock.
func (f *FileKeyStore) InitializeMasterKey(passphrase []byte) ([]byte, error) {
	// The .keystore metadata is in the identity directory (identities/<identityID>/).
	keystoreRoot := f.paths.KeystoreMetadataDir(f.identityID)

	// Load keystore metadata to get master salt
	meta, err := crypto.LoadKeystoreMetadata(keystoreRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to load keystore metadata: %w", err)
	}
	if meta == nil {
		return nil, fmt.Errorf("keystore not initialized (missing .keystore file in %s) - run migration first", keystoreRoot)
	}

	// Verify passphrase and derive master key
	masterKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to unlock keystore: %w", err)
	}

	f.cacheLock.Lock()
	// Zero old master key if present
	if f.masterKey != nil {
		crypto.ZeroBytes(f.masterKey)
	}
	f.masterKey = masterKey
	f.cacheLock.Unlock()

	return masterKey, nil
}

// Scan populates the internal cache by scanning the keys directory.
// If InitializeMasterKey was already called, the passphrase is ignored and
// the existing master key is reused. Otherwise, the passphrase is required
// to derive the master key.
// Each key is decrypted only once to extract address, type, and path.
func (f *FileKeyStore) Scan(passphrase []byte) error {
	f.cacheLock.RLock()
	masterKey := f.masterKey
	f.cacheLock.RUnlock()

	// If master key not already initialized, derive it now
	if masterKey == nil {
		if len(passphrase) == 0 {
			return fmt.Errorf("master key not initialized and no passphrase provided")
		}
		if _, err := f.InitializeMasterKey(passphrase); err != nil {
			return err
		}
	}

	// Re-read and hold RLock through the entire scan to prevent
	// ClearMasterKey() from zeroing the bytes mid-operation.
	// This also closes the gap after InitializeMasterKey returns.
	f.cacheLock.RLock()
	masterKey = f.masterKey
	if masterKey == nil {
		f.cacheLock.RUnlock()
		return fmt.Errorf("master key not available after initialization")
	}
	report, err := keys.ScanKeysDirectoryWithMasterKeyReport(f.paths, f.identityID, masterKey)
	f.cacheLock.RUnlock()
	if err != nil {
		return fmt.Errorf("failed to scan keys directory: %w", err)
	}

	f.cacheLock.Lock()
	f.cache = report.Keys
	f.scanWarnings = append([]keys.KeyScanWarning(nil), report.Warnings...)
	f.cacheLock.Unlock()

	return nil
}

// WithMasterKey executes fn while holding the cache read lock, ensuring
// the master key bytes cannot be zeroed by ClearMasterKey() during use.
// Returns an error if the master key is nil (keystore not unlocked).
func (f *FileKeyStore) WithMasterKey(fn func(masterKey []byte) error) error {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()
	if f.masterKey == nil {
		return fmt.Errorf("keystore not unlocked (master key not available): %w", ErrStoreLocked)
	}
	return fn(f.masterKey)
}

// ClearMasterKey securely zeros and removes the master key from memory.
// Called when the signer locks to ensure no key material remains resident.
func (f *FileKeyStore) ClearMasterKey() {
	f.cacheLock.Lock()
	if f.masterKey != nil {
		crypto.ZeroBytes(f.masterKey)
		f.masterKey = nil
	}
	f.cacheLock.Unlock()
}

// ClearCache removes scanned key metadata while preserving the unlocked master
// key. Reload fail-closed paths use this to ensure direct key lookups cannot
// use a rejected scan result.
func (f *FileKeyStore) ClearCache() {
	f.cacheLock.Lock()
	f.cache = make(map[string]keys.KeyScanInfo)
	f.scanWarnings = nil
	f.cacheLock.Unlock()
}

// List returns metadata for all available keys
func (f *FileKeyStore) List(ctx context.Context) ([]KeyMetadata, error) {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()

	result := make([]KeyMetadata, 0, len(f.cache))
	for address, info := range f.cache {
		meta := KeyMetadata{
			Address:     address,
			StorageType: "file",
			Exportable:  true,
			FilePath:    info.KeyFile,
			KeyType:     info.KeyType, // Now available from scan
		}

		if info.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, info.CreatedAt); err == nil {
				meta.CreatedAt = t
			}
		}
		if meta.CreatedAt.IsZero() {
			if fileInfo, err := os.Stat(info.KeyFile); err == nil {
				meta.CreatedAt = fileInfo.ModTime()
			}
		}

		result = append(result, meta)
	}

	return result, nil
}

// Get retrieves key material for signing.
// The keystore must be unlocked (via InitializeMasterKey or Scan) before calling Get.
// Holds the cache read lock through decryption to prevent ClearMasterKey() from
// zeroing the master key bytes mid-operation.
func (f *FileKeyStore) Get(ctx context.Context, address string) (*signing.KeyMaterial, error) {
	f.cacheLock.RLock()
	info, exists := f.cache[address]
	masterKey := f.masterKey
	if !exists {
		f.cacheLock.RUnlock()
		return nil, ErrKeyNotFound
	}
	if masterKey == nil {
		f.cacheLock.RUnlock()
		return nil, fmt.Errorf("keystore not unlocked (master key not available): %w", ErrStoreLocked)
	}
	// Read and decrypt the key file using master key (under RLock)
	decryptedData, err := keys.ReadDecryptedKeyJSONWithMasterKey(info.KeyFile, masterKey)
	f.cacheLock.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	defer crypto.ZeroBytes(decryptedData)

	payload, err := keys.ParsePayload(decryptedData)
	if err != nil {
		return nil, err
	}
	defer payload.ZeroSecrets()
	selector, err := payload.Selector()
	if err != nil {
		return nil, err
	}
	if selector != address {
		return nil, fmt.Errorf("key payload selector %s does not match requested selector %s", selector, address)
	}
	if payload.KeyType != info.KeyType || payload.Category != info.Category {
		return nil, fmt.Errorf("key payload identity changed after scan")
	}

	// Use key type from cache (already determined during scan)
	keyType := info.KeyType
	signingMeta := payload.SigningMetadata()

	// Generic lsig types (timelock, etc.) don't have signing providers
	// They only need bytecode attachment, no cryptographic signing
	if keys.IsGenericKey(signingMeta.Category) {
		return loadGenericLsigKeys(payload, keyType, signingMeta), nil
	}

	if keys.IsComponentKey(signingMeta.Category) {
		return loadComponentKeyMaterial(payload, keyType, signingMeta)
	}

	// Get provider and load keys (for ed25519, falcon, etc.)
	provider := signing.GetProviderForKey(keyType, signingMeta.BaseKeyType)
	if provider == nil {
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	providerKey := signing.ProviderKey{
		Type:        keyType,
		BaseKeyType: signingMeta.BaseKeyType,
		PrivateKey:  payload.PrivateKey,
	}
	km, err := provider.LoadKeyMaterial(providerKey)
	if err != nil {
		return nil, err
	}
	// The keystore owns the KeyMaterial envelope: storage metadata is stamped
	// unconditionally from the validated payload, so providers only supply
	// Type and the cryptographic Value.
	km.Category = signingMeta.Category
	km.BaseKeyType = signingMeta.BaseKeyType
	km.Bytecode = bytes.Clone(payload.LogicSigBytecode)
	km.PublicKey = bytes.Clone(payload.PublicKey)
	km.Parameters = maps.Clone(signingMeta.Parameters)
	km.SigningArgs = keys.SigningArgDefs(signingMeta.SigningArgs)
	km.SigningMetadataVersion = signingMeta.SigningMetadataVersion
	return km, nil
}

// GenericLsigData holds data for generic lsig types (timelock, etc.)
// These don't have cryptographic keys - just bytecode.
type GenericLsigData struct {
	BytecodeHex string
}

// loadGenericLsigKeys loads key material for generic lsig types (timelock, etc.)
// These don't have cryptographic keys - just bytecode that gets attached to transactions.
func loadGenericLsigKeys(payload *keys.Payload, keyType string, signingMeta keys.SigningMetadata) *signing.KeyMaterial {
	return &signing.KeyMaterial{
		Type:                   keyType,
		Category:               signingMeta.Category,
		Bytecode:               bytes.Clone(payload.LogicSigBytecode),
		Parameters:             maps.Clone(signingMeta.Parameters),
		SigningArgs:            keys.SigningArgDefs(signingMeta.SigningArgs),
		SigningMetadataVersion: signingMeta.SigningMetadataVersion,
		Value:                  &GenericLsigData{BytecodeHex: hex.EncodeToString(payload.LogicSigBytecode)},
	}
}

// loadComponentKeyMaterial projects an already-validated component payload
// into KeyMaterial. ParsePayload enforced the sentry key type, key sizes, and
// the public/private pair before Get reaches this point, so only cloning and
// selector derivation remain.
func loadComponentKeyMaterial(payload *keys.Payload, keyType string, signingMeta keys.SigningMetadata) (*signing.KeyMaterial, error) {
	publicKey := bytes.Clone(payload.PublicKey)
	privateKey := bytes.Clone(payload.PrivateKey)

	componentKey, err := keytypes.ComponentKeySelector(keyType, publicKey)
	if err != nil {
		crypto.ZeroBytes(publicKey)
		crypto.ZeroBytes(privateKey)
		return nil, err
	}

	return &signing.KeyMaterial{
		Type:       keyType,
		Category:   signingMeta.Category,
		PublicKey:  append([]byte(nil), publicKey...),
		Parameters: maps.Clone(signingMeta.Parameters),
		Value: &signing.ComponentKeyMaterial{
			ComponentKey: componentKey,
			PublicKey:    publicKey,
			PrivateKey:   privateKey,
		},
	}, nil
}

// GetMetadata returns metadata for a single key
func (f *FileKeyStore) GetMetadata(ctx context.Context, address string) (*KeyMetadata, error) {
	f.cacheLock.RLock()
	info, exists := f.cache[address]
	f.cacheLock.RUnlock()

	if !exists {
		return nil, ErrKeyNotFound
	}

	meta := &KeyMetadata{
		Address:     address,
		StorageType: "file",
		Exportable:  true,
		FilePath:    info.KeyFile,
		KeyType:     info.KeyType,
	}

	if info.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, info.CreatedAt); err == nil {
			meta.CreatedAt = t
		}
	}
	if meta.CreatedAt.IsZero() {
		if fileInfo, err := os.Stat(info.KeyFile); err == nil {
			meta.CreatedAt = fileInfo.ModTime()
		}
	}

	return meta, nil
}

// Delete removes a key from the store
func (f *FileKeyStore) Delete(ctx context.Context, address string) error {
	f.cacheLock.RLock()
	info, exists := f.cache[address]
	f.cacheLock.RUnlock()
	if !exists {
		return ErrKeyNotFound
	}

	// Remove the file
	if err := os.Remove(info.KeyFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete key file: %w", err)
	}

	f.cacheLock.Lock()
	if current, ok := f.cache[address]; ok && current.KeyFile == info.KeyFile {
		delete(f.cache, address)
	}
	f.cacheLock.Unlock()

	return nil
}

// Type returns the storage backend type
func (f *FileKeyStore) Type() string {
	return "file"
}

// GetKeyType returns the key type for an address.
// Uses cached key type from scan - no decryption needed.
func (f *FileKeyStore) GetKeyType(ctx context.Context, address string) (string, error) {
	f.cacheLock.RLock()
	info, exists := f.cache[address]
	f.cacheLock.RUnlock()

	if !exists {
		return "", ErrKeyNotFound
	}

	return info.KeyType, nil
}

// GetCache returns a copy of the address -> filepath cache
// This is useful for compatibility with existing code that expects this format
func (f *FileKeyStore) GetCache() map[string]string {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()

	result := make(map[string]string, len(f.cache))
	for k, v := range f.cache {
		result[k] = v.KeyFile
	}
	return result
}

// GetScanWarnings returns recoverable warnings from the most recent Scan.
func (f *FileKeyStore) GetScanWarnings() []keys.KeyScanWarning {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()
	return append([]keys.KeyScanWarning(nil), f.scanWarnings...)
}

// GetKeyTypes returns a copy of the address -> keyType cache
func (f *FileKeyStore) GetKeyTypes() map[string]string {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()

	result := make(map[string]string, len(f.cache))
	for k, v := range f.cache {
		result[k] = v.KeyType
	}
	return result
}

// GetSigningSummary returns one scan-time snapshot of address -> non-sensitive signing metadata.
func (f *FileKeyStore) GetSigningSummary() map[string]SigningSummary {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()

	result := make(map[string]SigningSummary, len(f.cache))
	for k, v := range f.cache {
		summary := SigningSummary{
			Category:               v.Category,
			Parameters:             maps.Clone(v.Parameters),
			SigningMetadataVersion: v.SigningMetadataVersion,
			TemplateFingerprint:    v.TemplateFingerprint,
		}
		if v.SigningMetadataVersion > 0 && len(v.SigningArgs) > 0 {
			summary.SigningArgs = keys.SigningArgDefs(v.SigningArgs)
		}
		result[k] = summary
	}
	return result
}

// GetLsigSizes returns a copy of the address -> lsigSize cache.
// LsigSize is the total LogicSig size in bytes (bytecode + signature).
// Returns 0 for Ed25519 keys (no LogicSig).
func (f *FileKeyStore) GetLsigSizes() map[string]int {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()

	result := make(map[string]int, len(f.cache))
	for k, v := range f.cache {
		result[k] = v.LsigSize
	}
	return result
}

// GetPublicKeyHexMap returns a copy of the address -> publicKeyHex cache.
// Used for the /keys endpoint. Returns empty string for generic LSig keys.
func (f *FileKeyStore) GetPublicKeyHexMap() map[string]string {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()

	result := make(map[string]string, len(f.cache))
	for k, v := range f.cache {
		result[k] = v.PublicKeyHex
	}
	return result
}

// Compile-time interface check
var (
	_ sessionKeyStore             = (*FileKeyStore)(nil)
	_ keys.KeyScanWarningProvider = (*FileKeyStore)(nil)
)
