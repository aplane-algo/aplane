// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keystore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
)

// testMasterKey is a 32-byte key for testing (AES-256 requires exactly 32 bytes)
var testMasterKey = []byte("test-master-key-32-bytes-long!!!")

// testKeyPair represents a minimal key pair for testing
type testKeyPair struct {
	KeyType       string `json:"key_type"`
	PublicKeyHex  string `json:"public_key"`
	PrivateKeyHex string `json:"private_key"`
}

// testIdentityID is the identity used in tests
const testIdentityID = "default"

// setupTestKeysDir creates a temporary keys directory and configures the keystore path.
// Returns the identity-scoped keys directory (store/users/default/keys/) and a cleanup function.
func setupTestKeysDir(t *testing.T) (string, func()) {
	t.Helper()

	tmpDir := t.TempDir()
	// Set keystore path to tmpDir, so KeysDir("default") returns tmpDir/users/default/keys
	keysDir := filepath.Join(tmpDir, "users", testIdentityID, "keys")
	if err := os.MkdirAll(keysDir, 0750); err != nil {
		t.Fatalf("Failed to create test keys dir: %v", err)
	}

	// Save old keystore path and set new one
	oldPath := utilkeys.KeystorePath()
	utilkeys.SetKeystorePath(tmpDir)

	cleanup := func() {
		utilkeys.SetKeystorePath(oldPath)
	}

	return keysDir, cleanup
}

// createTestKeyFile creates an encrypted test key file
// masterKey should be exactly 32 bytes for encryption
func createTestKeyFile(t *testing.T, keysDir, address string, masterKey []byte) string {
	t.Helper()

	// Generate a valid Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	keyPair := testKeyPair{
		KeyType:       "ed25519",
		PublicKeyHex:  hex.EncodeToString(pubKey),
		PrivateKeyHex: hex.EncodeToString(privKey),
	}

	keyJSON, err := json.MarshalIndent(keyPair, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}
	defer crypto.ZeroBytes(keyJSON)

	// Encrypt if master key provided
	var dataToWrite []byte
	if len(masterKey) > 0 {
		encrypted, err := crypto.EncryptWithMasterKey(keyJSON, masterKey)
		if err != nil {
			t.Fatalf("Failed to encrypt key: %v", err)
		}
		dataToWrite = encrypted
	} else {
		dataToWrite = make([]byte, len(keyJSON))
		copy(dataToWrite, keyJSON)
	}

	// Write to file
	filePath := filepath.Join(keysDir, address+".key")
	if err := os.WriteFile(filePath, dataToWrite, 0600); err != nil {
		t.Fatalf("Failed to write test key file: %v", err)
	}

	return filePath
}

// TestFileKeyStore_NewFileKeyStore tests store creation
func TestFileKeyStore_NewFileKeyStore(t *testing.T) {
	keysDir, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)
	if store == nil {
		t.Fatal("NewFileKeyStore returned nil")
	}

	if store.keysDir != keysDir {
		t.Errorf("keysDir = %s, want %s", store.keysDir, keysDir)
	}

	if store.cache == nil {
		t.Error("cache should be initialized")
	}
}

// TestFileKeyStore_NewFileKeyStore_DefaultPath tests default path handling
func TestFileKeyStore_NewFileKeyStore_DefaultPath(t *testing.T) {
	keysDir, cleanup := setupTestKeysDir(t)
	defer cleanup()

	// Create with default identity - should use KeysDir(identityID)
	store := NewFileKeyStore(testIdentityID)
	if store == nil {
		t.Fatal("NewFileKeyStore returned nil")
	}

	// Should use the configured keystore path with identity
	if store.keysDir != keysDir {
		t.Errorf("keysDir should be identity-scoped, got %s, want %s", store.keysDir, keysDir)
	}
}

// TestFileKeyStore_List_EmptyCache tests List with empty cache
func TestFileKeyStore_List_EmptyCache(t *testing.T) {
	_, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)
	ctx := context.Background()

	keys, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("Expected empty list, got %d keys", len(keys))
	}
}

// TestFileKeyStore_List_WithCache tests List returns cached keys
func TestFileKeyStore_List_WithCache(t *testing.T) {
	keysDir, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)
	ctx := context.Background()

	// Create a test file
	addr := "TESTADDR1234567890"
	filePath := createTestKeyFile(t, keysDir, addr, nil)

	// Manually add to cache (simulating scan)
	store.cache[addr] = keys.KeyScanInfo{KeyFile: filePath, KeyType: "ed25519"}

	keys, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("Expected 1 key, got %d", len(keys))
	}

	if keys[0].Address != addr {
		t.Errorf("Address = %s, want %s", keys[0].Address, addr)
	}

	if keys[0].StorageType != "file" {
		t.Errorf("StorageType = %s, want 'file'", keys[0].StorageType)
	}

	if !keys[0].Exportable {
		t.Error("FileKeyStore keys should be exportable")
	}
}

// TestFileKeyStore_Get_KeyNotFound tests Get for missing key
func TestFileKeyStore_Get_KeyNotFound(t *testing.T) {
	_, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)
	ctx := context.Background()

	_, err := store.Get(ctx, "NONEXISTENT")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

// TestFileKeyStore_GetMetadata tests metadata retrieval
func TestFileKeyStore_GetMetadata(t *testing.T) {
	keysDir, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)
	ctx := context.Background()

	// Add key to cache
	addr := "METADATATEST1234"
	filePath := createTestKeyFile(t, keysDir, addr, nil)
	store.cache[addr] = keys.KeyScanInfo{KeyFile: filePath, KeyType: "ed25519"}

	meta, err := store.GetMetadata(ctx, addr)
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}

	if meta.Address != addr {
		t.Errorf("Address = %s, want %s", meta.Address, addr)
	}

	if meta.FilePath != filePath {
		t.Errorf("FilePath = %s, want %s", meta.FilePath, filePath)
	}

	if meta.StorageType != "file" {
		t.Errorf("StorageType = %s, want 'file'", meta.StorageType)
	}
}

// TestFileKeyStore_GetMetadata_NotFound tests metadata for missing key
func TestFileKeyStore_GetMetadata_NotFound(t *testing.T) {
	_, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)
	ctx := context.Background()

	_, err := store.GetMetadata(ctx, "NONEXISTENT")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

// TestFileKeyStore_Store_Success tests storing a new key
func TestFileKeyStore_Store_Success(t *testing.T) {
	keysDir, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)
	ctx := context.Background()

	// Initialize master key (required for encryption)
	store.masterKey = testMasterKey

	addr := "NEWKEY123456789"

	// Create key data
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	keyPair := testKeyPair{
		KeyType:       "ed25519",
		PublicKeyHex:  hex.EncodeToString(pubKey),
		PrivateKeyHex: hex.EncodeToString(privKey),
	}
	keyData, _ := json.Marshal(keyPair)

	err := store.Store(ctx, addr, keyData)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Verify key is in cache
	if _, exists := store.cache[addr]; !exists {
		t.Error("Key should be in cache after Store")
	}

	// Verify file was created
	expectedPath := filepath.Join(keysDir, addr[:8]+".priv")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Error("Key file should exist after Store")
	}
}

// TestFileKeyStore_Store_KeyExists tests storing duplicate key
func TestFileKeyStore_Store_KeyExists(t *testing.T) {
	keysDir, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)
	ctx := context.Background()

	addr := "DUPLICATE1234567"

	// Add to cache to simulate existing key
	store.cache[addr] = keys.KeyScanInfo{KeyFile: filepath.Join(keysDir, addr+".key"), KeyType: "ed25519"}

	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	keyPair := testKeyPair{
		KeyType:       "ed25519",
		PublicKeyHex:  hex.EncodeToString(pubKey),
		PrivateKeyHex: hex.EncodeToString(privKey),
	}
	keyData, _ := json.Marshal(keyPair)

	err := store.Store(ctx, addr, keyData)
	if err != ErrKeyExists {
		t.Errorf("Expected ErrKeyExists, got %v", err)
	}
}

// TestFileKeyStore_Delete_Success tests deleting a key
func TestFileKeyStore_Delete_Success(t *testing.T) {
	keysDir, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)
	ctx := context.Background()

	// Create test key
	addr := "DELETETEST12345"
	filePath := createTestKeyFile(t, keysDir, addr, nil)
	store.cache[addr] = keys.KeyScanInfo{KeyFile: filePath, KeyType: "ed25519"}

	err := store.Delete(ctx, addr)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify removed from cache
	if _, exists := store.cache[addr]; exists {
		t.Error("Key should be removed from cache after Delete")
	}

	// Verify file was deleted
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("Key file should be deleted")
	}
}

// TestFileKeyStore_Delete_NotFound tests deleting non-existent key
func TestFileKeyStore_Delete_NotFound(t *testing.T) {
	_, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)
	ctx := context.Background()

	err := store.Delete(ctx, "NONEXISTENT")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

// TestFileKeyStore_Export_Success tests exporting a key
func TestFileKeyStore_Export_Success(t *testing.T) {
	keysDir, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)
	ctx := context.Background()

	// Create test key
	addr := "EXPORTTEST12345"
	filePath := createTestKeyFile(t, keysDir, addr, testMasterKey)
	store.cache[addr] = keys.KeyScanInfo{KeyFile: filePath, KeyType: "ed25519"}

	data, err := store.Export(ctx, addr)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("Exported data should not be empty")
	}

	// Should be encrypted JSON
	if !crypto.IsEncrypted(data) {
		t.Error("Exported data should be encrypted")
	}
}

// TestFileKeyStore_Export_NotFound tests exporting non-existent key
func TestFileKeyStore_Export_NotFound(t *testing.T) {
	_, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)
	ctx := context.Background()

	_, err := store.Export(ctx, "NONEXISTENT")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

// TestFileKeyStore_SupportsExport tests SupportsExport returns true
func TestFileKeyStore_SupportsExport(t *testing.T) {
	store := NewFileKeyStore("dummy-identity")
	if !store.SupportsExport() {
		t.Error("FileKeyStore should support export")
	}
}

// TestFileKeyStore_Type tests Type returns "file"
func TestFileKeyStore_Type(t *testing.T) {
	store := NewFileKeyStore("dummy-identity")
	if store.Type() != "file" {
		t.Errorf("Type = %s, want 'file'", store.Type())
	}
}

// TestFileKeyStore_GetCache tests cache copy
func TestFileKeyStore_GetCache(t *testing.T) {
	_, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)

	// Add some entries to cache
	store.cache["addr1"] = keys.KeyScanInfo{KeyFile: "/path/to/key1", KeyType: "ed25519"}
	store.cache["addr2"] = keys.KeyScanInfo{KeyFile: "/path/to/key2", KeyType: "falcon1024-v1"}

	cache := store.GetCache()

	// Verify it's a copy with just file paths
	if len(cache) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(cache))
	}

	// Verify it returns file paths
	if cache["addr1"] != "/path/to/key1" {
		t.Errorf("Expected /path/to/key1, got %s", cache["addr1"])
	}

	// Modify the returned cache - should not affect original
	cache["addr3"] = "/path/to/key3"
	if len(store.cache) != 2 {
		t.Error("GetCache should return a copy, not the original map")
	}
}

// TestFileKeyStore_GetKeyTypes tests key types cache copy
func TestFileKeyStore_GetKeyTypes(t *testing.T) {
	_, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)

	// Add some entries to cache
	store.cache["addr1"] = keys.KeyScanInfo{KeyFile: "/path/to/key1", KeyType: "ed25519"}
	store.cache["addr2"] = keys.KeyScanInfo{KeyFile: "/path/to/key2", KeyType: "falcon1024-v1"}

	keyTypes := store.GetKeyTypes()

	// Verify it's a copy with just key types
	if len(keyTypes) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(keyTypes))
	}

	// Verify it returns key types
	if keyTypes["addr1"] != "ed25519" {
		t.Errorf("Expected ed25519, got %s", keyTypes["addr1"])
	}
	if keyTypes["addr2"] != "falcon1024-v1" {
		t.Errorf("Expected falcon1024-v1, got %s", keyTypes["addr2"])
	}
}

// TestFileKeyStore_CacheConcurrency tests thread-safe cache operations
func TestFileKeyStore_CacheConcurrency(t *testing.T) {
	_, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStore(testIdentityID)
	ctx := context.Background()

	const numGoroutines = 50
	const numIterations = 100

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines*numIterations)

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				_, err := store.List(ctx)
				if err != nil {
					errChan <- err
				}
				_ = store.GetCache()
				_ = store.GetKeyTypes()
			}
		}()
	}

	// Concurrent writes via lock (simulating Scan updates)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				store.cacheLock.Lock()
				store.cache = map[string]keys.KeyScanInfo{
					"key": {KeyFile: "/path", KeyType: "ed25519"},
				}
				store.cacheLock.Unlock()
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Check for any errors
	for err := range errChan {
		t.Errorf("Concurrent operation error: %v", err)
	}
}

// TestFileKeyStore_InterfaceCompliance verifies interface implementation
func TestFileKeyStore_InterfaceCompliance(t *testing.T) {
	// This is a compile-time check that FileKeyStore implements KeyStore
	var _ KeyStore = (*FileKeyStore)(nil)
}
