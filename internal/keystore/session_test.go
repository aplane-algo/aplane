// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/signing"
	ed25519signing "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
)

func init() {
	// Register ed25519 provider for integration tests
	ed25519signing.RegisterProvider()
}

// mockKeyStore implements sessionKeyStore for testing KeySession
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

// TestKeySession_NewKeySession tests session creation
func TestKeySession_NewKeySession(t *testing.T) {
	store := newMockKeyStore()

	session := NewKeySession(store)
	switch {
	case session == nil:
		t.Fatal("NewKeySession returned nil")
	case session.keyStore != store:
		t.Error("keyStore not set correctly")
	case session.active:
		t.Error("session should not be active initially")
	}
}

// TestKeySession_InitializeSession tests session initialization
func TestKeySession_InitializeSession(t *testing.T) {
	store := newMockKeyStore()
	session := NewKeySession(store)

	session.InitializeSession()

	if !session.active {
		t.Fatal("session should be active after InitializeSession")
	}
}

// TestKeySession_GetKey_ActiveSession tests GetKey with active session
func TestKeySession_GetKey_ActiveSession(t *testing.T) {
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
	session.InitializeSession()

	key, err := session.GetKey(testAddr)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	switch {
	case key == nil:
		t.Fatal("key should not be nil")
	case key.Type != "ed25519":
		t.Errorf("key.Type = %s, want ed25519", key.Type)
	}
}

// TestKeySession_GetKey_InactiveSession tests GetKey when session is not active
func TestKeySession_GetKey_InactiveSession(t *testing.T) {
	store := newMockKeyStore()

	store.keys["TESTADDR"] = &signing.KeyMaterial{
		Type:  "ed25519",
		Value: []byte("test-key-data"),
	}

	session := NewKeySession(store)
	// Don't initialize - session is inactive

	_, err := session.GetKey("TESTADDR")
	if err == nil {
		t.Fatal("expected error from inactive session")
	}
}

// TestKeySession_GetKey_KeyNotFound tests error handling
func TestKeySession_GetKey_KeyNotFound(t *testing.T) {
	store := newMockKeyStore()
	session := NewKeySession(store)
	session.InitializeSession()

	_, err := session.GetKey("NONEXISTENT")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

// TestKeySession_Destroy tests cleanup
func TestKeySession_Destroy(t *testing.T) {
	store := newMockKeyStore()
	session := NewKeySession(store)

	// Initialize session
	session.InitializeSession()

	if !session.active {
		t.Fatal("session should be active before Destroy")
	}

	session.Destroy()

	if session.active {
		t.Error("session should not be active after Destroy")
	}
}

// TestKeySession_Concurrency tests thread-safe operations
func TestKeySession_Concurrency(t *testing.T) {
	store := newMockKeyStore()
	store.keys["ADDR1"] = &signing.KeyMaterial{Type: "ed25519", Value: []byte("key1")}
	store.keys["ADDR2"] = &signing.KeyMaterial{Type: "ed25519", Value: []byte("key2")}

	session := NewKeySession(store)
	session.InitializeSession()

	const numGoroutines = 20
	const numIterations = 50

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines*numIterations)

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
				_, err := session.GetKey(addr)
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
	// tmpDir/keystore/identities/default/keys/*.key (key files)
	tmpDir := t.TempDir()
	keystoreRoot := filepath.Join(tmpDir, "keystore")
	keysDir := filepath.Join(keystoreRoot, "identities", "default", "keys")
	if err := os.MkdirAll(keysDir, 0750); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}

	masterKeyRing, err := crypto.NewKeyring()
	if err != nil {
		t.Fatalf("Failed to create keystore metadata: %v", err)
	}

	// Generate ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	payload := keys.NewEd25519Payload(pubKey, privKey)
	defer payload.ZeroSecrets()
	payload.CreatedAt = time.Date(2026, 7, 10, 12, 34, 56, 0, time.UTC)
	testAddr, err := payload.Selector()
	if err != nil {
		t.Fatalf("Selector() error = %v", err)
	}
	keyJSON, err := keys.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload() error = %v", err)
	}

	encrypted, err := masterKeyRing.Seal(keyJSON, crypto.AccountKeyContext(testAddr))
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	crypto.ZeroBytes(keyJSON)

	keyFile := filepath.Join(keysDir, testAddr+".key")
	if err := os.WriteFile(keyFile, encrypted, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create FileKeyStore and set up cache and master key
	fileStore := NewAtomicFileKeyStoreForPaths(utilkeys.NewPaths(keystoreRoot))
	fileStore.cache[testAddr] = keys.KeyScanInfo{KeyFile: keyFile, KeyType: "ed25519", Category: keys.CategoryEd25519}
	fileStore.setKeyringDirectlyForTest(masterKeyRing)

	// Create KeySession with FileKeyStore
	session := NewKeySession(fileStore)

	// Initialize session (master key is already in the fileStore)
	session.InitializeSession()

	// Get the key
	key, err := session.GetKey(testAddr)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	switch {
	case key == nil:
		t.Fatal("key should not be nil")
	case key.Type != "ed25519":
		t.Errorf("key.Type = %s, want ed25519", key.Type)
	case key.Value == nil:
		t.Error("key.Value should not be nil")
	}
}
