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

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

// FileKeyStore implements KeyStore using encrypted files on disk
type FileKeyStore struct {
	paths  storepaths.Paths
	active *storepaths.GenPaths

	// Cache of address -> KeyScanInfo (populated by Scan)
	// Contains both file path and key type from single decrypt
	cache        map[string]keys.KeyScanInfo
	scanWarnings []keys.KeyScanWarning
	cacheLock    sync.RWMutex

	// The store's keyring, opened once at unlock and zeroed on lock.
	keyring *crypto.Keyring
}

// SigningSummary is the non-sensitive key-file signing metadata cached at scan time.
type SigningSummary struct {
	Category               string
	Parameters             map[string]string
	SigningArgs            []lsigprovider.RuntimeArgDef
	BoundedAuthorization   *boundedmeta.Metadata
	SigningMetadataVersion int
	TemplateFingerprint    string
	LogicSigResources      *lsigresource.Profile
}

// NewAtomicFileKeyStoreForPaths creates a file store whose unlock and reload
// authenticate generation selection from store-root.enc.
func NewAtomicFileKeyStoreForPaths(paths storepaths.Paths) *FileKeyStore {
	return &FileKeyStore{
		paths: paths,
		cache: make(map[string]keys.KeyScanInfo),
	}
}

// Unlock opens the store's keyring with the passphrase and holds it for the
// session.
//
// A successful unwrap is the passphrase check, so there is no separate
// verifier to consult. Callers receive no key material: the keyring hands out
// operations, not bytes.
func (f *FileKeyStore) Unlock(passphrase []byte) error {
	resolved, kr, err := genstore.OpenStoreRootSelection(f.paths, passphrase)
	if err != nil {
		return fmt.Errorf("failed to unlock keystore: %w", err)
	}
	f.cacheLock.Lock()
	if f.keyring != nil {
		f.keyring.Zero()
	}
	f.keyring = kr
	f.active = &resolved
	f.cacheLock.Unlock()
	return nil
}

// Scan populates the internal cache by scanning the keys directory.
// If Unlock was already called, the passphrase is ignored and the existing
// keyring is reused. Otherwise the passphrase is required to open it.
// Each key is decrypted only once to extract address, type, and path.
func (f *FileKeyStore) Scan(passphrase []byte) error {
	f.cacheLock.RLock()
	unlocked := f.keyring != nil
	f.cacheLock.RUnlock()

	if !unlocked {
		if len(passphrase) == 0 {
			return fmt.Errorf("keystore not unlocked and no passphrase provided")
		}
		if err := f.Unlock(passphrase); err != nil {
			return err
		}
	}

	// Re-read and hold RLock through the entire scan to prevent
	// ClearKeys() from zeroing the terms mid-operation. This also closes the
	// gap after Unlock returns.
	f.cacheLock.RLock()
	if f.keyring == nil {
		f.cacheLock.RUnlock()
		return fmt.Errorf("keystore not unlocked after unlock")
	}
	// Resolve the active layout once per scan. Atomic stores authenticate a
	// fresh exact root read while the keyring is held, so every reload after a
	// root commit rebuilds the cache against the newly selected generation.
	resolvedAtomic, resolveErr := genstore.ResolveStoreRootWithKeyring(f.paths, f.keyring)
	if resolveErr != nil {
		f.cacheLock.RUnlock()
		return fmt.Errorf("failed to resolve active key store layout: %w", resolveErr)
	}
	report, err := keys.ScanKeysDirectoryWithKeyringReportActive(resolvedAtomic, f.keyring)
	f.cacheLock.RUnlock()
	if err != nil {
		return fmt.Errorf("failed to scan keys directory: %w", err)
	}

	f.cacheLock.Lock()
	f.active = &resolvedAtomic
	f.cache = report.Keys
	f.scanWarnings = append([]keys.KeyScanWarning(nil), report.Warnings...)
	f.cacheLock.Unlock()

	return nil
}

// WithKeyring executes fn with the store's keyring while holding the cache
// read lock, so no term can be zeroed mid-use. This is the API callers
// should use: it hands out operations, not key material.
func (f *FileKeyStore) WithKeyring(fn func(kr *crypto.Keyring) error) error {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()
	if f.keyring == nil {
		return fmt.Errorf("keystore not unlocked (keyring not available): %w", ErrStoreLocked)
	}
	return fn(f.keyring)
}

// ClearKeys securely zeros every term key and drops the keyring. Called when
// the signer locks so no key material remains resident.
func (f *FileKeyStore) ClearKeys() {
	f.cacheLock.Lock()
	if f.keyring != nil {
		f.keyring.Zero()
		f.keyring = nil
	}
	f.active = nil
	f.cacheLock.Unlock()
}

// ActivePaths returns the generation authenticated by the most recent atomic
// root unlock or reload. The returned value is a copy and carries no key
// material.
func (f *FileKeyStore) ActivePaths() (storepaths.GenPaths, error) {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()
	if f.keyring == nil {
		return storepaths.GenPaths{}, fmt.Errorf("store is not unlocked: %w", ErrStoreLocked)
	}
	if f.active == nil {
		return storepaths.GenPaths{}, fmt.Errorf("atomic store root is not unlocked: %w", ErrStoreLocked)
	}
	return *f.active, nil
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
// The keystore must be unlocked (via Unlock or Scan) before calling Get.
// Holds the cache read lock through decryption to prevent ClearKeys() from
// zeroing the term keys mid-operation.
func (f *FileKeyStore) Get(ctx context.Context, address string) (*signing.KeyMaterial, error) {
	f.cacheLock.RLock()
	info, exists := f.cache[address]
	if !exists {
		f.cacheLock.RUnlock()
		return nil, ErrKeyNotFound
	}
	if f.keyring == nil {
		f.cacheLock.RUnlock()
		return nil, fmt.Errorf("keystore not unlocked: %w", ErrStoreLocked)
	}
	// Decrypt under the read lock, straight from the keyring: no term key
	// copy is made, so none can outlive the lock or survive ClearKeys.
	decryptedData, err := keys.ReadDecryptedKeyJSONWithKeyring(info.KeyFile, f.keyring)
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

	if keys.IsWitnessKey(signingMeta.Category) {
		return loadWitnessKeyMaterial(payload, keyType, signingMeta)
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
	km.PQScheme = signingMeta.PQScheme
	if signingMeta.PQAddressSalt != nil {
		salt := *signingMeta.PQAddressSalt
		km.PQAddressSalt = &salt
	}
	km.BaseKeyType = signingMeta.BaseKeyType
	km.Bytecode = bytes.Clone(payload.LogicSigBytecode)
	km.PublicKey = bytes.Clone(payload.PublicKey)
	km.Parameters = maps.Clone(signingMeta.Parameters)
	km.SigningArgs = keys.SigningArgDefs(signingMeta.SigningArgs)
	km.BoundedAuthorization = boundedmeta.Clone(signingMeta.BoundedAuthorization)
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
		BoundedAuthorization:   boundedmeta.Clone(signingMeta.BoundedAuthorization),
		SigningMetadataVersion: signingMeta.SigningMetadataVersion,
		Value:                  &GenericLsigData{BytecodeHex: hex.EncodeToString(payload.LogicSigBytecode)},
	}
}

// loadWitnessKeyMaterial projects an already-validated witness payload into
// KeyMaterial. ParsePayload enforced the witness key type, key sizes, and
// the public/private pair before Get reaches this point, so only cloning and
// selector derivation remain.
func loadWitnessKeyMaterial(payload *keys.Payload, keyType string, signingMeta keys.SigningMetadata) (*signing.KeyMaterial, error) {
	publicKey := bytes.Clone(payload.PublicKey)
	privateKey := bytes.Clone(payload.PrivateKey)

	componentKey, err := witness.ID(keyType, publicKey)
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
		Value: &signing.WitnessKeyMaterial{
			WitnessKeyID: componentKey,
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
	if f.keyring == nil {
		f.cacheLock.RUnlock()
		return fmt.Errorf("keystore mutation blocked: %w", ErrStoreLocked)
	}
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

// GetSigningSummary returns one scan-time snapshot of address -> non-sensitive
// signing metadata. The returned map, its Parameters maps, and its
// BoundedAuthorization records are freshly built per call and owned by the
// caller — no further defensive cloning is required.
func (f *FileKeyStore) GetSigningSummary() map[string]SigningSummary {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()

	result := make(map[string]SigningSummary, len(f.cache))
	for k, v := range f.cache {
		summary := SigningSummary{
			Category:               v.Category,
			Parameters:             maps.Clone(v.Parameters),
			SigningMetadataVersion: v.SigningMetadataVersion,
			BoundedAuthorization:   boundedmeta.Clone(v.BoundedAuthorization),
			TemplateFingerprint:    v.TemplateFingerprint,
		}
		if v.LogicSigResources != nil {
			cloned := v.LogicSigResources.Clone()
			summary.LogicSigResources = &cloned
		}
		if v.SigningMetadataVersion > 0 && len(v.SigningArgs) > 0 {
			summary.SigningArgs = keys.SigningArgDefs(v.SigningArgs)
		}
		result[k] = summary
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
