// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
	falconkeygen "github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

// testMasterKey is a 32-byte key for testing (AES-256 requires exactly 32 bytes)
var testMasterKey = []byte("test-master-key-32-bytes-long!!!")

// testKeyPair represents a minimal key pair for testing
type testKeyPair struct {
	KeyType       string `json:"key_type"`
	PublicKeyHex  string `json:"public_key"`
	PrivateKeyHex string `json:"private_key"`
}

// setupTestKeysDir creates a temporary keys directory and explicit keystore paths.
// Returns the product-store keys directory, path helper, and a cleanup function.
func setupTestKeysDir(t *testing.T) (string, utilkeys.Paths, func()) {
	t.Helper()

	tmpDir := t.TempDir()
	paths := utilkeys.NewPaths(tmpDir)
	genstoretest.MintFirst(t, paths)
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		t.Fatalf("ResolveActive: %v", err)
	}
	return active.KeysDir(), paths, func() {}
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

	filePath := filepath.Join(keysDir, address+".key")
	var dataToWrite []byte
	if len(masterKey) > 0 {
		encrypted, err := cryptotest.Keyring(t, masterKey).Seal(keyJSON, crypto.AccountKeyContext(address))
		if err != nil {
			t.Fatalf("Failed to encrypt key: %v", err)
		}
		dataToWrite = encrypted
	} else {
		dataToWrite = make([]byte, len(keyJSON))
		copy(dataToWrite, keyJSON)
	}

	if err := os.WriteFile(filePath, dataToWrite, 0600); err != nil {
		t.Fatalf("Failed to write test key file: %v", err)
	}

	return filePath
}

// TestFileKeyStore_NewFileKeyStore tests store creation
func TestFileKeyStore_NewFileKeyStore(t *testing.T) {
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths)
	switch {
	case store == nil:
		t.Fatal("NewFileKeyStoreForPaths returned nil")
	case store.paths.Root() != paths.Root():
		t.Errorf("store root = %s, want %s", store.paths.Root(), paths.Root())
	case store.cache == nil:
		t.Error("cache should be initialized")
	}
}

// TestFileKeyStore_NewFileKeyStore_DefaultPath tests default path handling
func TestFileKeyStore_NewFileKeyStore_DefaultPath(t *testing.T) {
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	// Scanning resolves the fixed product store's active layout per operation.
	store := NewFileKeyStoreForPaths(paths)
	if store == nil {
		t.Fatal("NewFileKeyStoreForPaths returned nil")
	}
	if store.paths.ProductDir() != paths.ProductDir() {
		t.Errorf("product dir = %s, want %s", store.paths.ProductDir(), paths.ProductDir())
	}
}

// TestFileKeyStore_List_EmptyCache tests List with empty cache
func TestFileKeyStore_List_EmptyCache(t *testing.T) {
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths)
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

	store := NewFileKeyStoreForPaths(paths)
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

	store := NewFileKeyStoreForPaths(paths)
	ctx := context.Background()

	_, err := store.Get(ctx, "NONEXISTENT")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestFileKeyStore_GetDecryptFailureIsNotInvalidPassphrase(t *testing.T) {
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths)
	if err := store.setKeyringForTest(testMasterKey); err != nil {
		t.Fatalf("setKeyringForTest(): %v", err)
	}
	ctx := context.Background()

	addr := "CORRUPTEDKEY123"
	encrypted, err := cryptotest.Keyring(t, testMasterKey).Seal([]byte(`{"key_type":"ed25519"}`), crypto.AccountKeyContext(addr))
	if err != nil {
		t.Fatalf("encryptWithTermKey failed: %v", err)
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

	store := NewFileKeyStoreForPaths(paths)
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

	store := NewFileKeyStoreForPaths(paths)
	ctx := context.Background()

	_, err := store.GetMetadata(ctx, "NONEXISTENT")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

// TestFileKeyStore_Store_Success tests storing a new key
// TestFileKeyStore_Delete_Success tests deleting a key
func TestFileKeyStore_Delete_Success(t *testing.T) {
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths)
	store.keyring = cryptotest.Keyring(t, testMasterKey)
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

	store := NewFileKeyStoreForPaths(paths)
	store.keyring = cryptotest.Keyring(t, testMasterKey)
	ctx := context.Background()

	err := store.Delete(ctx, "NONEXISTENT")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestFileKeyStoreDeleteKeepsCacheWhenRemoveFails(t *testing.T) {
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths)
	store.keyring = cryptotest.Keyring(t, testMasterKey)
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

// TestFileKeyStore_Type tests Type returns "file"
func TestFileKeyStore_Type(t *testing.T) {
	dummyPaths := utilkeys.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, dummyPaths)
	store := NewFileKeyStoreForPaths(dummyPaths)
	if store.Type() != "file" {
		t.Errorf("Type = %s, want 'file'", store.Type())
	}
}

// TestFileKeyStore_GetCache tests cache copy
func TestFileKeyStore_GetCache(t *testing.T) {
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths)

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

	store := NewFileKeyStoreForPaths(paths)

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

	store := NewFileKeyStoreForPaths(paths)
	store.cache["addr1"] = keys.KeyScanInfo{
		Category:               keys.CategoryDSALsig,
		Parameters:             map[string]string{"sentry_public_key": "abc123"},
		SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
		SigningArgs: []keys.StoredSigningArg{
			{Name: "proof", Type: "bytes", Required: true, ByteLength: 32},
		},
		TemplateFingerprint: "semantic-a",
		LogicSigResources: &lsigresource.Profile{
			ProgramBytes: 10,
			Default:      &lsigresource.PathProfile{ArgumentBytes: 20, MaxOpcodeCost: 30},
		},
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
	got.LogicSigResources.Default.ArgumentBytes = 999
	if store.cache["addr1"].LogicSigResources.Default.ArgumentBytes != 20 {
		t.Fatal("GetSigningSummary should deep-clone LogicSig resource profiles")
	}
}

func TestFileKeyStoreScanRejectsComponentPublicPrivateMismatch(t *testing.T) {
	falconkeygen.RegisterWitnessKeygen()
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	publicKey, _, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x51}, 64))
	if err != nil {
		t.Fatalf("GenerateKey(public) error = %v", err)
	}
	_, privateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0x52}, 64))
	if err != nil {
		t.Fatalf("GenerateKey(private) error = %v", err)
	}
	componentKey, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	keyJSON, err := json.Marshal(map[string]any{
		"format_version": keys.CurrentKeyFormatVersion,
		"category":       keys.CategoryWitness,
		"key_type":       witness.Falcon1024V1,
		"public_key":     hex.EncodeToString(publicKey),
		"private_key":    hex.EncodeToString(privateKey),
		"created_at":     "2026-07-10T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("json.Marshal(component key) error = %v", err)
	}
	encrypted, err := cryptotest.Keyring(t, testMasterKey).Seal(keyJSON, crypto.SentryCredentialContext(componentKey))
	if err != nil {
		t.Fatalf("encryptWithTermKey() error = %v", err)
	}
	if err := os.WriteFile(keys.SentryCredentialFilePath(paths, componentKey), encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile(component key) error = %v", err)
	}

	report, err := keys.ScanKeysDirectoryWithKeyringReport(paths, cryptotest.Keyring(t, testMasterKey))
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithKeyringReport() error = %v", err)
	}
	if len(report.Keys) != 0 || len(report.Warnings) != 1 {
		t.Fatalf("scan report = %#v, want one rejected key", report)
	}
	if !strings.Contains(report.Warnings[0].Reason(), "witness public key does not match private key") {
		t.Fatalf("scan warning = %v, want witness key mismatch", report.Warnings[0])
	}
}

func TestFileKeyStoreScanRejectsPendingRotation(t *testing.T) {
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	passphrase := []byte("pending-rotation-passphrase")
	keystoreDir := paths.KeystoreMetadataDir()
	kr, err := crypto.CreateKeyringStore(keystoreDir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	if err := crypto.StartRotation(
		keystoreDir,
		kr,
		passphrase,
		[]crypto.HistoricalGenerationAnchor{},
		func(target *crypto.Keyring, _, _ int64) (crypto.RotationSnapshotReference, error) {
			sealed, err := target.Seal([]byte("cutover"), crypto.RotationSnapshotContext())
			if err != nil {
				return crypto.RotationSnapshotReference{}, err
			}
			return crypto.NewRotationSnapshotReference(sealed)
		},
	); err != nil {
		kr.Zero()
		t.Fatalf("StartRotation() error = %v", err)
	}
	kr.Zero()

	store := NewFileKeyStoreForPaths(paths)
	if err := store.Unlock(passphrase); err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}
	t.Cleanup(store.ClearKeys)
	err = store.Scan(nil)
	if !errors.Is(err, crypto.ErrRotationPending) ||
		!strings.Contains(err.Error(), "rotation 1 -> 2 requires resume") {
		t.Fatalf("Scan() error = %v, want pending rotation failure", err)
	}
	callbackCalled := false
	err = store.WithKeyring(func(*crypto.Keyring) error {
		callbackCalled = true
		return nil
	})
	if !errors.Is(err, crypto.ErrRotationPending) {
		t.Fatalf("WithKeyring() error = %v, want pending rotation failure", err)
	}
	if callbackCalled {
		t.Fatal("WithKeyring() exposed a pending keyring to an ordinary runtime caller")
	}
	keyPath := createTestKeyFile(t, keysDir, "PENDINGDELETE", nil)
	store.cache["PENDINGDELETE"] = keys.KeyScanInfo{
		KeyFile: keyPath,
		KeyType: "ed25519",
	}
	err = store.Delete(context.Background(), "PENDINGDELETE")
	if !errors.Is(err, crypto.ErrRotationPending) {
		t.Fatalf("Delete() error = %v, want pending rotation failure", err)
	}
	if _, statErr := os.Stat(keyPath); statErr != nil {
		t.Fatalf("Delete() removed a snapshot-pinned key during rotation: %v", statErr)
	}
}

func TestFileKeyStoreDeleteRejectsLockedStoreWithCachedEntry(t *testing.T) {
	keysDir, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths)
	keyPath := createTestKeyFile(t, keysDir, "LOCKEDDELETE", nil)
	store.cache["LOCKEDDELETE"] = keys.KeyScanInfo{
		KeyFile: keyPath,
		KeyType: "ed25519",
	}
	err := store.Delete(context.Background(), "LOCKEDDELETE")
	if !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("Delete() error = %v, want locked-store failure", err)
	}
	if _, statErr := os.Stat(keyPath); statErr != nil {
		t.Fatalf("Delete() removed a cached key while locked: %v", statErr)
	}
}

// TestFileKeyStore_CacheConcurrency tests thread-safe cache operations
func TestFileKeyStore_CacheConcurrency(t *testing.T) {
	_, paths, cleanup := setupTestKeysDir(t)
	defer cleanup()

	store := NewFileKeyStoreForPaths(paths)
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

// TestClearKeysBlocksDuringWithKeyring proves that ClearKeys() blocks while
// a WithKeyring callback is running (RLock held).
func TestClearKeysBlocksDuringWithKeyring(t *testing.T) {
	fs := &FileKeyStore{cache: map[string]keys.KeyScanInfo{}}
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0xAB
	}
	if err := fs.setKeyringForTest(key); err != nil {
		t.Fatalf("setKeyringForTest(): %v", err)
	}

	started := make(chan struct{})
	cleared := make(chan struct{})

	// Hold the RLock via WithKeyring for a bit
	go func() {
		_ = fs.WithKeyring(func(kr *crypto.Keyring) error {
			close(started) // signal we're inside the callback
			time.Sleep(100 * time.Millisecond)
			// The keyring must still be usable here, which is what the
			// read lock guarantees against a concurrent ClearKeys.
			if _, err := kr.Seal([]byte("probe"), crypto.AccountKeyContext("PROBE")); err != nil {
				t.Errorf("keyring unusable while WithKeyring callback was running: %v", err)
				return nil
			}
			return nil
		})
	}()

	<-started // wait for callback to be running

	// ClearKeys should block until callback returns
	go func() {
		fs.ClearKeys()
		close(cleared)
	}()

	// cleared should not fire for ~100ms (while callback holds RLock)
	select {
	case <-cleared:
		t.Fatal("ClearKeys completed while WithKeyring callback was still running")
	case <-time.After(50 * time.Millisecond):
		// expected — ClearKeys is still blocked
	}

	// Now wait for both to finish
	<-cleared

	// Verify the keyring was actually dropped
	if fs.keyringIsLoaded() {
		t.Error("keyring should be gone after ClearKeys")
	}
}
