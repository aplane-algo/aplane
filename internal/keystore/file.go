// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keystore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/signing"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
)

// FileKeyStore implements KeyStore using encrypted files on disk
type FileKeyStore struct {
	keysDir    string
	identityID string // Identity used for scanning (e.g., "default")

	// Cache of address -> KeyScanInfo (populated by Scan)
	// Contains both file path and key type from single decrypt
	cache     map[string]keys.KeyScanInfo
	cacheLock sync.RWMutex

	// Master key for envelope_version 2 decryption
	// Derived once during Scan() from keystore metadata salt
	masterKey []byte
}

// NewFileKeyStore creates a new file-based key store.
// identityID scopes key operations to a specific identity directory (e.g., "default").
func NewFileKeyStore(identityID string) *FileKeyStore {
	return &FileKeyStore{
		keysDir:    utilkeys.KeysDir(identityID),
		identityID: identityID,
		cache:      make(map[string]keys.KeyScanInfo),
	}
}

// InitializeMasterKey derives and stores the master key from the passphrase.
// This should be called before Scan() when you need the master key early
// (e.g., for template scanning that happens before key scanning).
// Returns the master key for external use (e.g., template scanning).
// Caller should NOT zero the returned key - it's owned by FileKeyStore.
func (f *FileKeyStore) InitializeMasterKey(passphrase []byte) ([]byte, error) {
	// The .keystore metadata is in the keystore root.
	// keysDir is store/users/<identityID>/keys, so root is three levels up.
	keystoreRoot := utilkeys.KeystorePath()

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
// This requires a passphrase to derive the master key and decrypt keys.
// If InitializeMasterKey was already called, this reuses the existing master key.
// Each key is decrypted only once to extract address, type, and path.
// Call this at startup after obtaining the passphrase.
func (f *FileKeyStore) Scan(passphrase []byte) error {
	f.cacheLock.RLock()
	masterKey := f.masterKey
	f.cacheLock.RUnlock()

	// If master key not already initialized, derive it now
	if masterKey == nil {
		var err error
		masterKey, err = f.InitializeMasterKey(passphrase)
		if err != nil {
			return err
		}
	}

	// Scan keys using master key
	keysMap, err := keys.ScanKeysDirectoryWithMasterKey(f.identityID, masterKey)
	if err != nil {
		return fmt.Errorf("failed to scan keys directory: %w", err)
	}

	f.cacheLock.Lock()
	f.cache = keysMap
	f.cacheLock.Unlock()

	return nil
}

// GetMasterKey returns the master key for decryption.
// This is used by callers that need to decrypt key files.
// Caller must NOT zero the returned key - it's owned by FileKeyStore.
func (f *FileKeyStore) GetMasterKey() []byte {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()
	return f.masterKey
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
func (f *FileKeyStore) Get(ctx context.Context, address string) (*signing.KeyMaterial, error) {
	f.cacheLock.RLock()
	info, exists := f.cache[address]
	masterKey := f.masterKey
	f.cacheLock.RUnlock()

	if !exists {
		return nil, ErrKeyNotFound
	}

	if masterKey == nil {
		return nil, fmt.Errorf("keystore not unlocked (master key not available)")
	}

	// Read and decrypt the key file using master key
	decryptedData, err := keys.ReadDecryptedKeyJSONWithMasterKey(info.KeyFile, masterKey)
	if err != nil {
		if strings.Contains(err.Error(), "decrypt") {
			return nil, ErrInvalidPassphrase
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	defer crypto.ZeroBytes(decryptedData)

	// Extract bytecode if present (for LogicSig-based keys)
	bytecode := extractBytecode(decryptedData)

	// Use key type from cache (already determined during scan)
	keyType := info.KeyType

	// Generic lsig types (timelock, etc.) don't have signing providers
	// They only need bytecode attachment, no cryptographic signing
	if keys.IsGenericLSigType(keyType) {
		km, err := loadGenericLsigKeys(decryptedData, keyType)
		if err != nil {
			return nil, err
		}
		km.Bytecode = bytecode
		return km, nil
	}

	// Get provider and load keys (for ed25519, falcon, etc.)
	provider := signing.GetProvider(keyType)
	if provider == nil {
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	km, err := provider.LoadKeysFromData(decryptedData)
	if err != nil {
		return nil, err
	}
	km.Bytecode = bytecode // Set bytecode (nil for native ed25519, populated for falcon LSig)
	return km, nil
}

// extractBytecode extracts LogicSig bytecode from decrypted key data.
// Returns nil if no bytecode is present (e.g., native ed25519 keys).
func extractBytecode(decryptedData []byte) []byte {
	var keyData struct {
		LsigBytecode string `json:"lsig_bytecode"`
		BytecodeHex  string `json:"bytecode_hex"`
	}
	if err := json.Unmarshal(decryptedData, &keyData); err != nil {
		return nil
	}

	// Use lsig_bytecode if present, otherwise bytecode_hex
	bytecodeHex := keyData.LsigBytecode
	if bytecodeHex == "" {
		bytecodeHex = keyData.BytecodeHex
	}
	if bytecodeHex == "" {
		return nil
	}

	bytecode, err := hex.DecodeString(bytecodeHex)
	if err != nil {
		return nil
	}
	return bytecode
}

// GenericLsigData holds data for generic lsig types (timelock, etc.)
// These don't have cryptographic keys - just bytecode.
type GenericLsigData struct {
	BytecodeHex string
}

// loadGenericLsigKeys loads key material for generic lsig types (timelock, etc.)
// These don't have cryptographic keys - just bytecode that gets attached to transactions.
func loadGenericLsigKeys(decryptedData []byte, keyType string) (*signing.KeyMaterial, error) {
	var keyData struct {
		LsigBytecode string `json:"lsig_bytecode"`
		BytecodeHex  string `json:"bytecode_hex"`
	}
	if err := json.Unmarshal(decryptedData, &keyData); err != nil {
		return nil, fmt.Errorf("failed to parse generic lsig key data: %w", err)
	}

	// Get bytecode from either field
	bytecodeHex := keyData.LsigBytecode
	if bytecodeHex == "" {
		bytecodeHex = keyData.BytecodeHex
	}

	return &signing.KeyMaterial{
		Type:  keyType,
		Value: &GenericLsigData{BytecodeHex: bytecodeHex},
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

// Store saves a new key to the store.
// Note: This method is not part of the KeyStore interface - it's FileKeyStore-specific.
// Keys are typically generated via keymgmt which writes files directly and calls Scan().
// The keystore must be unlocked (master key available) before calling Store.
func (f *FileKeyStore) Store(ctx context.Context, address string, keyData []byte) error {
	// Check if key already exists
	f.cacheLock.RLock()
	_, exists := f.cache[address]
	masterKey := f.masterKey
	f.cacheLock.RUnlock()

	if exists {
		return ErrKeyExists
	}

	// Determine filename from address (first 8 chars)
	filename := address
	if len(filename) > 8 {
		filename = filename[:8]
	}
	filePath := filepath.Join(f.keysDir, filename+".priv")

	// Check if file already exists on disk
	if _, err := os.Stat(filePath); err == nil {
		return ErrKeyExists
	}

	// Encrypt with master key (required)
	if masterKey == nil {
		return fmt.Errorf("master key required for encryption")
	}
	encrypted, err := crypto.EncryptWithMasterKey(keyData, masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %w", err)
	}
	dataToWrite := encrypted

	// Write with secure permissions
	if err := os.WriteFile(filePath, dataToWrite, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	// Update cache - key type unknown until Scan() is called
	f.cacheLock.Lock()
	f.cache[address] = keys.KeyScanInfo{KeyFile: filePath, KeyType: "unknown"}
	f.cacheLock.Unlock()

	return nil
}

// Delete removes a key from the store
func (f *FileKeyStore) Delete(ctx context.Context, address string) error {
	f.cacheLock.Lock()
	info, exists := f.cache[address]
	if !exists {
		f.cacheLock.Unlock()
		return ErrKeyNotFound
	}
	delete(f.cache, address)
	f.cacheLock.Unlock()

	// Remove the file
	if err := os.Remove(info.KeyFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete key file: %w", err)
	}

	return nil
}

// Export returns the encrypted key data
func (f *FileKeyStore) Export(ctx context.Context, address string) ([]byte, error) {
	f.cacheLock.RLock()
	info, exists := f.cache[address]
	f.cacheLock.RUnlock()

	if !exists {
		return nil, ErrKeyNotFound
	}

	data, err := os.ReadFile(info.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return data, nil
}

// SupportsExport returns true for file-based storage
func (f *FileKeyStore) SupportsExport() bool {
	return true
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

// GetPublicKeyInfo returns public key information for a single key.
// Used for the /keys endpoint. Keystore must be unlocked.
func (f *FileKeyStore) GetPublicKeyInfo(ctx context.Context, address string) (*PublicKeyInfo, error) {
	f.cacheLock.RLock()
	info, exists := f.cache[address]
	masterKey := f.masterKey
	f.cacheLock.RUnlock()

	if !exists {
		return nil, ErrKeyNotFound
	}

	if masterKey == nil {
		return nil, fmt.Errorf("keystore not unlocked (master key not available)")
	}

	// Read and decrypt the key file using master key
	decryptedData, err := keys.ReadDecryptedKeyJSONWithMasterKey(info.KeyFile, masterKey)
	if err != nil {
		if strings.Contains(err.Error(), "decrypt") {
			return nil, ErrInvalidPassphrase
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	defer crypto.ZeroBytes(decryptedData)

	// Parse public key info
	var keyData struct {
		PublicKeyHex    string `json:"public_key"`
		LsigBytecodeHex string `json:"lsig_bytecode"`
		BytecodeHex     string `json:"bytecode_hex"` // Fallback field for LogicSig keys
	}
	if err := json.Unmarshal(decryptedData, &keyData); err != nil {
		return nil, fmt.Errorf("failed to parse key data: %w", err)
	}

	// Use cached key type
	keyType := info.KeyType

	// Use lsig_bytecode if present, otherwise bytecode_hex
	bytecodeHex := keyData.LsigBytecodeHex
	if bytecodeHex == "" {
		bytecodeHex = keyData.BytecodeHex
	}

	return &PublicKeyInfo{
		Address:         address,
		KeyType:         keyType,
		PublicKeyHex:    keyData.PublicKeyHex,
		LsigBytecodeHex: bytecodeHex,
	}, nil
}

// GetAllPublicKeyInfo returns public key information for all keys in the store.
// This is more efficient than calling GetPublicKeyInfo for each key individually.
// Keys that fail to load (corrupted, I/O errors) are logged and skipped.
// Keystore must be unlocked.
func (f *FileKeyStore) GetAllPublicKeyInfo() ([]PublicKeyInfo, error) {
	// Create a snapshot of the cache
	f.cacheLock.RLock()
	addresses := make([]string, 0, len(f.cache))
	for addr := range f.cache {
		addresses = append(addresses, addr)
	}
	f.cacheLock.RUnlock()

	ctx := context.Background()
	result := make([]PublicKeyInfo, 0, len(addresses))

	for _, address := range addresses {
		// Safe truncation for logging (addresses should be 58 chars, but be defensive)
		addrPrefix := address
		if len(addrPrefix) > 8 {
			addrPrefix = addrPrefix[:8]
		}

		info, err := f.GetPublicKeyInfo(ctx, address)
		if err != nil {
			// Log and skip keys that fail to load (I/O error, parse error, etc.)
			// Common cause: key file deleted after scan but before read
			fmt.Printf("Warning: skipping key %s: %v\n", addrPrefix, err)
			continue
		}
		result = append(result, *info)
	}

	return result, nil
}

// PublicKeyInfo contains public (non-sensitive) key information
type PublicKeyInfo struct {
	Address         string
	KeyType         string
	PublicKeyHex    string
	LsigBytecodeHex string
}

// Compile-time interface check
var _ KeyStore = (*FileKeyStore)(nil)
