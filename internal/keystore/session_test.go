// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keystore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/signing"
	ed25519signing "github.com/aplane-algo/aplane/internal/signing/ed25519"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
)

func init() {
	// Register ed25519 provider for integration tests
	ed25519signing.RegisterProvider()
}

// mockKeyStore implements KeyStore for testing KeySession
type mockKeyStore struct {
	keys     map[string]*signing.KeyMaterial
	getError error
	getCalls int
	mu       sync.Mutex
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{
		keys: make(map[string]*signing.KeyMaterial),
	}
}

func (m *mockKeyStore) List(ctx context.Context) ([]KeyMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []KeyMetadata
	for addr := range m.keys {
		result = append(result, KeyMetadata{Address: addr})
	}
	return result, nil
}

func (m *mockKeyStore) Get(ctx context.Context, address string) (*signing.KeyMaterial, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCalls++

	if m.getError != nil {
		return nil, m.getError
	}

	key, ok := m.keys[address]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

func (m *mockKeyStore) GetMetadata(ctx context.Context, address string) (*KeyMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[address]; !ok {
		return nil, ErrKeyNotFound
	}
	return &KeyMetadata{Address: address}, nil
}

func (m *mockKeyStore) Delete(ctx context.Context, address string) error {
	return nil
}

func (m *mockKeyStore) Type() string {
	return "mock"
}

// TestKeySession_NewKeySession tests session creation
func TestKeySession_NewKeySession(t *testing.T) {
	store := newMockKeyStore()

	session := NewKeySession(store)
	if session == nil {
		t.Fatal("NewKeySession returned nil")
	}
	if session.keyStore != store {
		t.Error("keyStore not set correctly")
	}
	if session.passphrase != nil {
		t.Error("passphrase should be nil initially")
	}
}

// TestKeySession_InitializeSession tests session initialization with passphrase
func TestKeySession_InitializeSession(t *testing.T) {
	store := newMockKeyStore()
	session := NewKeySession(store)

	passphrase := []byte("test-passphrase")
	session.InitializeSession(passphrase)

	if session.passphrase == nil {
		t.Fatal("passphrase should be set after InitializeSession")
	}

	if session.passphrase.IsEmpty() {
		t.Error("passphrase should not be empty")
	}
}

// TestKeySession_GetKey_SessionMode tests GetKey with cached passphrase
func TestKeySession_GetKey_SessionMode(t *testing.T) {
	store := newMockKeyStore()

	// Add a test key
	testAddr := "TESTADDR123"
	testKey := &signing.KeyMaterial{
		Type:  "ed25519",
		Value: []byte("test-key-data"),
	}
	store.keys[testAddr] = testKey

	session := NewKeySession(store)

	// Initialize session
	passphrase := []byte("test-passphrase")
	session.InitializeSession(passphrase)

	// Should not prompt - passphrase is cached
	promptCalled := false
	promptFunc := func() ([]byte, error) {
		promptCalled = true
		return []byte("prompted-pass"), nil
	}

	key, err := session.GetKey(testAddr, promptFunc)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if promptCalled {
		t.Error("promptFunc should not be called when passphrase is cached")
	}

	if key == nil {
		t.Fatal("key should not be nil")
	}

	if key.Type != "ed25519" {
		t.Errorf("key.Type = %s, want ed25519", key.Type)
	}
}

// TestKeySession_GetKey_NeedsPrompt tests GetKey when no passphrase cached
func TestKeySession_GetKey_NeedsPrompt(t *testing.T) {
	store := newMockKeyStore()

	testAddr := "TESTADDR123"
	store.keys[testAddr] = &signing.KeyMaterial{
		Type:  "ed25519",
		Value: []byte("test-key-data"),
	}

	session := NewKeySession(store)
	// Don't initialize - should need to prompt

	promptCalled := false
	promptFunc := func() ([]byte, error) {
		promptCalled = true
		return []byte("user-passphrase"), nil
	}

	key, err := session.GetKey(testAddr, promptFunc)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if !promptCalled {
		t.Error("promptFunc should be called when no passphrase cached")
	}

	if key == nil {
		t.Fatal("key should not be nil")
	}

	// Verify passphrase was cached for next call
	if session.passphrase == nil || session.passphrase.IsEmpty() {
		t.Error("passphrase should be cached after prompt")
	}
}

// TestKeySession_GetKey_KeyNotFound tests error handling
func TestKeySession_GetKey_KeyNotFound(t *testing.T) {
	store := newMockKeyStore()
	session := NewKeySession(store)
	session.InitializeSession([]byte("test-pass"))

	promptFunc := func() ([]byte, error) {
		return []byte("pass"), nil
	}

	_, err := session.GetKey("NONEXISTENT", promptFunc)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

// TestKeySession_GetKey_PromptError tests prompt function error handling
func TestKeySession_GetKey_PromptError(t *testing.T) {
	store := newMockKeyStore()
	store.keys["TESTADDR"] = &signing.KeyMaterial{Type: "ed25519"}

	session := NewKeySession(store)
	// Don't initialize - will need to prompt

	promptErr := errors.New("prompt failed")
	promptFunc := func() ([]byte, error) {
		return nil, promptErr
	}

	_, err := session.GetKey("TESTADDR", promptFunc)
	if err == nil {
		t.Fatal("expected error from prompt")
	}
}

// TestKeySession_Destroy tests cleanup
func TestKeySession_Destroy(t *testing.T) {
	store := newMockKeyStore()
	session := NewKeySession(store)

	// Initialize with passphrase
	session.InitializeSession([]byte("test-passphrase"))

	if session.passphrase == nil {
		t.Fatal("passphrase should be set before Destroy")
	}

	session.Destroy()

	if session.passphrase != nil {
		t.Error("passphrase should be nil after Destroy")
	}
}

// TestKeySession_Concurrency tests thread-safe operations
func TestKeySession_Concurrency(t *testing.T) {
	store := newMockKeyStore()
	store.keys["ADDR1"] = &signing.KeyMaterial{Type: "ed25519", Value: []byte("key1")}
	store.keys["ADDR2"] = &signing.KeyMaterial{Type: "ed25519", Value: []byte("key2")}

	session := NewKeySession(store)
	session.InitializeSession([]byte("test-pass"))

	const numGoroutines = 20
	const numIterations = 50

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines*numIterations)

	promptFunc := func() ([]byte, error) {
		return []byte("pass"), nil
	}

	// Concurrent GetKey calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			addr := "ADDR1"
			if id%2 == 0 {
				addr = "ADDR2"
			}
			for j := 0; j < numIterations; j++ {
				_, err := session.GetKey(addr, promptFunc)
				if err != nil {
					errChan <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("concurrent GetKey error: %v", err)
	}
}

// TestKeySession_IntegrationWithFileKeyStore tests the full integration
func TestKeySession_IntegrationWithFileKeyStore(t *testing.T) {
	// Setup test directory with proper keystore structure:
	// tmpDir/keystore/.keystore (metadata)
	// tmpDir/keystore/users/default/keys/*.key (key files)
	tmpDir := t.TempDir()
	keystoreRoot := filepath.Join(tmpDir, "keystore")
	keysDir := filepath.Join(keystoreRoot, "users", "default", "keys")
	if err := os.MkdirAll(keysDir, 0750); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}

	oldPath := utilkeys.KeystorePath()
	utilkeys.SetKeystorePath(keystoreRoot)
	defer utilkeys.SetKeystorePath(oldPath)

	// Create keystore metadata for master key encryption (v2) in user directory
	passphrase := []byte("integration-test-pass")
	userDir := filepath.Join(keystoreRoot, "users", "default")
	_, masterKey, err := crypto.CreateKeystoreMetadata(userDir, passphrase)
	if err != nil {
		t.Fatalf("Failed to create keystore metadata: %v", err)
	}
	defer crypto.ZeroBytes(masterKey)

	// Generate ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	keyData := struct {
		KeyType       string `json:"key_type"`
		PublicKeyHex  string `json:"public_key"`
		PrivateKeyHex string `json:"private_key"`
	}{
		KeyType:       "ed25519",
		PublicKeyHex:  hex.EncodeToString(pubKey),
		PrivateKeyHex: hex.EncodeToString(privKey),
	}

	keyJSON, _ := json.MarshalIndent(keyData, "", "  ")

	// Encrypt with master key (v2 format)
	encrypted, err := crypto.EncryptWithMasterKey(keyJSON, masterKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	crypto.ZeroBytes(keyJSON)

	// Use a proper Algorand-style address for the filename
	testAddr := "TESTINTEGRATION1234"
	keyFile := filepath.Join(keysDir, testAddr+".key")
	if err := os.WriteFile(keyFile, encrypted, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create FileKeyStore and set up cache and master key
	fileStore := NewFileKeyStore("default")
	fileStore.cache[testAddr] = keys.KeyScanInfo{KeyFile: keyFile, KeyType: "ed25519"}
	// Copy the master key (since it will be zeroed in the defer)
	fileStore.masterKey = make([]byte, len(masterKey))
	copy(fileStore.masterKey, masterKey)

	// Create KeySession with FileKeyStore
	session := NewKeySession(fileStore)

	// Initialize with passphrase
	session.InitializeSession(passphrase)

	// Get the key
	promptFunc := func() ([]byte, error) {
		t.Error("prompt should not be called")
		return nil, errors.New("unexpected prompt")
	}

	key, err := session.GetKey(testAddr, promptFunc)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if key == nil {
		t.Fatal("key should not be nil")
	}

	if key.Type != "ed25519" {
		t.Errorf("key.Type = %s, want ed25519", key.Type)
	}

	// Verify it's actual key material
	if key.Value == nil {
		t.Error("key.Value should not be nil")
	}
}
