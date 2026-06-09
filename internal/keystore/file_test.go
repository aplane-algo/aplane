// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
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

// setupTestKeysDir creates a temporary keys directory and explicit keystore paths.
// Returns the identity-scoped keys directory, path helper, and a cleanup function.
func setupTestKeysDir(t *testing.T) (string, utilkeys.Paths, func()) {
	t.Helper()

	tmpDir := t.TempDir()
	// Set keystore path to tmpDir, so KeysDir("default") returns tmpDir/identities/default/keys
	keysDir := filepath.Join(tmpDir, "identities", testIdentityID, "keys")
	if err := os.MkdirAll(keysDir, 0750); err != nil {
		t.Fatalf("Failed to create test keys dir: %v", err)
	}

	return keysDir, utilkeys.NewPaths(tmpDir), func() {}
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
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
	switch {
	case store == nil:
		t.Fatal("NewFileKeyStoreForPaths returned nil")
	case store.keysDir != keysDir:
		t.Errorf("keysDir = %s, want %s", store.keysDir, keysDir)
	case store.cache == nil:
		t.Error("cache should be initialized")
	}
}

// TestFileKeyStore_NewFileKeyStore_DefaultPath tests default path handling
func TestFileKeyStore_NewFileKeyStore_DefaultPath(t *testing.T) {
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	// Create with default identity - should use KeysDir(identityID)
	store := NewFileKeyStoreForPaths(paths, testIdentityID)
	switch {
	case store == nil:
		t.Fatal("NewFileKeyStoreForPaths returned nil")
	case store.keysDir != keysDir:
		// Should use the configured keystore path with identity
		t.Errorf("keysDir should be identity-scoped, got %s, want %s", store.keysDir, keysDir)
	}
}

// TestFileKeyStore_List_EmptyCache tests List with empty cache
func TestFileKeyStore_List_EmptyCache(t *testing.T) {
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
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
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
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
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
	ctx := context.Background()

	_, err := store.Get(ctx, "NONEXISTENT")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestFileKeyStore_GetDecryptFailureIsNotInvalidPassphrase(t *testing.T) {
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
	store.masterKey = testMasterKey
	ctx := context.Background()

	addr := "CORRUPTEDKEY123"
	encrypted, err := crypto.EncryptWithMasterKey([]byte(`{"key_type":"ed25519"}`), testMasterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey failed: %v", err)
	}

	var envelope struct {
		EnvelopeVersion int    `json:"envelope_version"`
		Nonce           string `json:"nonce"`
		Ciphertext      string `json:"ciphertext"`
	}
	if err := json.Unmarshal(encrypted, &envelope); err != nil {
		t.Fatalf("Unmarshal encrypted envelope failed: %v", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		t.Fatalf("DecodeString ciphertext failed: %v", err)
	}
	ciphertext[0] ^= 0x01
	envelope.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	corrupted, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Marshal corrupted envelope failed: %v", err)
	}

	filePath := filepath.Join(keysDir, addr+".key")
	if err := os.WriteFile(filePath, corrupted, 0600); err != nil {
		t.Fatalf("WriteFile corrupted key failed: %v", err)
	}
	store.cache[addr] = keys.KeyScanInfo{KeyFile: filePath, KeyType: "ed25519"}

	_, err = store.Get(ctx, addr)
	if err == nil {
		t.Fatal("Get() error = nil, want decrypt failure")
	}
	if errors.Is(err, ErrInvalidPassphrase) {
		t.Fatalf("Get() error = %v, should not be ErrInvalidPassphrase for key file corruption", err)
	}
}

// TestFileKeyStore_GetMetadata tests metadata retrieval
func TestFileKeyStore_GetMetadata(t *testing.T) {
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
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
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
	ctx := context.Background()

	_, err := store.GetMetadata(ctx, "NONEXISTENT")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

// TestFileKeyStore_Store_Success tests storing a new key
func TestFileKeyStore_Store_Success(t *testing.T) {
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
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
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
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
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
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
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
	ctx := context.Background()

	err := store.Delete(ctx, "NONEXISTENT")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestFileKeyStoreDeleteKeepsCacheWhenRemoveFails(t *testing.T) {
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
	ctx := context.Background()

	addr := "DELETEFAIL12345"
	blockingDir := filepath.Join(keysDir, "nonempty")
	if err := os.MkdirAll(blockingDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(blockingDir) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(blockingDir, "child"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocking child) error = %v", err)
	}
	store.cache[addr] = keys.KeyScanInfo{KeyFile: blockingDir, KeyType: "ed25519"}

	err := store.Delete(ctx, addr)
	if err == nil {
		t.Fatal("Delete() error = nil, want remove failure")
	}
	if _, exists := store.cache[addr]; !exists {
		t.Fatal("cache entry was evicted despite remove failure")
	}
}

// TestFileKeyStore_Export_Success tests exporting a key
func TestFileKeyStore_Export_Success(t *testing.T) {
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
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
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
	ctx := context.Background()

	_, err := store.Export(ctx, "NONEXISTENT")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

// TestFileKeyStore_SupportsExport tests SupportsExport returns true
func TestFileKeyStore_SupportsExport(t *testing.T) {
	store := NewFileKeyStoreForPaths(utilkeys.NewPaths(t.TempDir()), "dummy-identity")
	if !store.SupportsExport() {
		t.Error("FileKeyStore should support export")
	}
}

// TestFileKeyStore_Type tests Type returns "file"
func TestFileKeyStore_Type(t *testing.T) {
	store := NewFileKeyStoreForPaths(utilkeys.NewPaths(t.TempDir()), "dummy-identity")
	if store.Type() != "file" {
		t.Errorf("Type = %s, want 'file'", store.Type())
	}
}

// TestFileKeyStore_GetCache tests cache copy
func TestFileKeyStore_GetCache(t *testing.T) {
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)

	// Add some entries to cache
	store.cache["addr1"] = keys.KeyScanInfo{KeyFile: "/path/to/key1", KeyType: "ed25519"}
	store.cache["addr2"] = keys.KeyScanInfo{KeyFile: "/path/to/key2", KeyType: "aplane.falcon1024.v1"}

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
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)

	// Add some entries to cache
	store.cache["addr1"] = keys.KeyScanInfo{KeyFile: "/path/to/key1", KeyType: "ed25519"}
	store.cache["addr2"] = keys.KeyScanInfo{KeyFile: "/path/to/key2", KeyType: "aplane.falcon1024.v1"}

	keyTypes := store.GetKeyTypes()

	// Verify it's a copy with just key types
	if len(keyTypes) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(keyTypes))
	}

	// Verify it returns key types
	if keyTypes["addr1"] != "ed25519" {
		t.Errorf("Expected ed25519, got %s", keyTypes["addr1"])
	}
	if keyTypes["addr2"] != "aplane.falcon1024.v1" {
		t.Errorf("Expected aplane.falcon1024.v1, got %s", keyTypes["addr2"])
	}
}

func TestFileKeyStore_GetSigningSummary(t *testing.T) {
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
	store.cache["addr1"] = keys.KeyScanInfo{
		Category:               keys.CategoryDSALsig,
		Parameters:             map[string]string{"sentry_public_key": "abc123"},
		SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
		SigningArgs: []keys.StoredSigningArg{
			{Name: "proof", Type: "bytes", Required: true, ByteLength: 32},
		},
		TemplateFingerprint: "semantic-a",
	}

	summary := store.GetSigningSummary()
	got := summary["addr1"]
	if got.Category != keys.CategoryDSALsig {
		t.Fatalf("Category = %q, want %q", got.Category, keys.CategoryDSALsig)
	}
	if got.SigningMetadataVersion != keys.CurrentSigningMetadataVersion {
		t.Fatalf("SigningMetadataVersion = %d, want %d", got.SigningMetadataVersion, keys.CurrentSigningMetadataVersion)
	}
	if got.TemplateFingerprint != "semantic-a" {
		t.Fatalf("TemplateFingerprint = %q, want semantic-a", got.TemplateFingerprint)
	}
	if got.Parameters["sentry_public_key"] != "abc123" {
		t.Fatalf("Parameters = %#v, want sentry_public_key", got.Parameters)
	}
	if len(got.SigningArgs) != 1 || got.SigningArgs[0].Name != "proof" {
		t.Fatalf("SigningArgs = %+v, want proof arg", got.SigningArgs)
	}

	got.Parameters["sentry_public_key"] = "mutated"
	if store.cache["addr1"].Parameters["sentry_public_key"] != "abc123" {
		t.Fatal("GetSigningSummary should return a copy, not mutate cached parameters")
	}

	got.SigningArgs[0].Name = "mutated"
	if store.cache["addr1"].SigningArgs[0].Name != "proof" {
		t.Fatal("GetSigningSummary should return a copy, not mutate cached signing args")
	}
}

func TestFileKeyStore_GetRejectsComponentPublicPrivateMismatch(t *testing.T) {
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(public) error = %v", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(private) error = %v", err)
	}
	componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentEd25519V1, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	keyPair := &keys.KeyPair{
		Category:      keys.CategoryComponent,
		KeyType:       keytypes.SentryComponentEd25519V1,
		PublicKeyHex:  hex.EncodeToString(publicKey),
		PrivateKeyHex: hex.EncodeToString(privateKey),
	}
	if _, err := keys.SaveKeyFile(paths, keyPair, testIdentityID, componentKey, testMasterKey); err != nil {
		t.Fatalf("SaveKeyFile() error = %v", err)
	}

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
	store.masterKey = append([]byte(nil), testMasterKey...)
	defer crypto.ZeroBytes(store.masterKey)
	if err := store.Scan(nil); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	_, err = store.Get(context.Background(), componentKey)
	if err == nil {
		t.Fatal("Get() error = nil, want public/private mismatch")
	}
	if !strings.Contains(err.Error(), "sentry public key does not match private key") {
		t.Fatalf("Get() error = %v, want sentry key mismatch", err)
	}
}

// TestFileKeyStore_CacheConcurrency tests thread-safe cache operations
func TestFileKeyStore_CacheConcurrency(t *testing.T) {
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths, testIdentityID)
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
				_ = store.GetSigningSummary()
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

// TestClearMasterKeyBlocksDuringWithMasterKey proves that ClearMasterKey()
// blocks while a WithMasterKey callback is running (RLock held).
func TestClearMasterKeyBlocksDuringWithMasterKey(t *testing.T) {
	fs := &FileKeyStore{
		cache:     map[string]keys.KeyScanInfo{},
		masterKey: make([]byte, 32),
	}
	// Fill with non-zero bytes
	for i := range fs.masterKey {
		fs.masterKey[i] = 0xAB
	}

	started := make(chan struct{})
	cleared := make(chan struct{})

	// Hold the RLock via WithMasterKey for a bit
	go func() {
		_ = fs.WithMasterKey(func(mk []byte) error {
			close(started) // signal we're inside the callback
			time.Sleep(100 * time.Millisecond)
			// Master key should still be non-zero here
			for _, b := range mk {
				if b == 0 {
					t.Errorf("master key was zeroed while WithMasterKey callback was running")
					return nil
				}
			}
			return nil
		})
	}()

	<-started // wait for callback to be running

	// ClearMasterKey should block until callback returns
	go func() {
		fs.ClearMasterKey()
		close(cleared)
	}()

	// cleared should not fire for ~100ms (while callback holds RLock)
	select {
	case <-cleared:
		t.Fatal("ClearMasterKey completed while WithMasterKey callback was still running")
	case <-time.After(50 * time.Millisecond):
		// expected — ClearMasterKey is still blocked
	}

	// Now wait for both to finish
	<-cleared

	// Verify master key was actually cleared
	if fs.masterKey != nil {
		t.Error("master key should be nil after ClearMasterKey")
	}
}

// TestFileKeyStore_InterfaceCompliance verifies interface implementation
func TestFileKeyStore_InterfaceCompliance(t *testing.T) {
	// This is a compile-time check that FileKeyStore implements KeyStore
	var _ KeyStore = (*FileKeyStore)(nil)
}
