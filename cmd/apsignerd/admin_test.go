// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/util"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// testPassphrase is a fixed passphrase for test keystore creation.
var testPassphrase = []byte("test-passphrase-for-unit-tests!")

// setupTestSigner creates a Signer with a working keystore, unlocked hub,
// and identity context ready for handler testing.
// Returns the signer and a cleanup function. The caller should defer cleanup().
func setupTestSigner(t *testing.T) (*Signer, func()) {
	t.Helper()

	tmpDir := t.TempDir()

	// Create identity-scoped keys directory
	keysDir := filepath.Join(tmpDir, "users", "default", "keys")
	if err := os.MkdirAll(keysDir, 0750); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}

	// Save and restore global keystore path
	oldPath := utilkeys.KeystorePath()
	utilkeys.SetKeystorePath(tmpDir)

	// Create keystore metadata (.keystore file with master salt)
	_, _, err := crypto.CreateKeystoreMetadata(tmpDir, testPassphrase)
	if err != nil {
		utilkeys.SetKeystorePath(oldPath)
		t.Fatalf("Failed to create keystore metadata: %v", err)
	}

	// Initialize FileKeyStore and derive master key
	ks := keystore.NewFileKeyStore(auth.DefaultIdentityID)
	_, err = ks.InitializeMasterKey(testPassphrase)
	if err != nil {
		utilkeys.SetKeystorePath(oldPath)
		t.Fatalf("Failed to initialize master key: %v", err)
	}

	server := &Signer{
		keyStore:     ks,
		keys:         map[string]map[string]string{auth.DefaultIdentityID: {}},
		keyTypes:     map[string]map[string]string{auth.DefaultIdentityID: {}},
		keyLsigSizes: map[string]map[string]int{auth.DefaultIdentityID: {}},
		config:       &util.ServerConfig{},
	}
	server.hub = NewHub(server)
	server.hub.SetUnlocked()

	cleanup := func() {
		utilkeys.SetKeystorePath(oldPath)
	}

	return server, cleanup
}

// requestWithIdentity creates an HTTP request with an authenticated identity in the context.
func requestWithIdentity(method, url string, body []byte) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, url, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, url, nil)
	}
	identity := auth.NewDefaultIdentity("test")
	ctx := auth.ContextWithIdentity(r.Context(), identity)
	return r.WithContext(ctx)
}

// decodeResponse decodes the JSON response body into the given target.
func decodeResponse(t *testing.T, w *httptest.ResponseRecorder, target interface{}) {
	t.Helper()
	if err := json.NewDecoder(w.Body).Decode(target); err != nil {
		t.Fatalf("Failed to decode response: %v (body: %s)", err, w.Body.String())
	}
}

// mockAlgodServer creates a mock algod HTTP server that handles /v2/teal/compile.
// It returns bytecode that contains the bytecblock pattern expected by falcon1024
// key generation ({0x26, 0x01, 0x01, counter}).
func mockAlgodServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/teal/compile" {
			// Build bytecode with the bytecblock pattern that falcon1024 expects.
			// Structure: version(0x0c) + bytecblock(0x26,0x01,0x01,0x00) + padding
			// The padding needs to be large enough that the resulting LogicSig address
			// hash doesn't accidentally land on the ed25519 curve (extremely unlikely
			// with random-looking bytes, but we add enough to be safe).
			bytecode := []byte{
				0x0c,                   // #pragma version 12
				0x26, 0x01, 0x01, 0x00, // bytecblock 0x00 (counter at offset 4)
				0x31, 0x17, // txn TxID
				0x2d,       // arg 0
				0x81, 0x01, // int 1 (placeholder)
			}
			// Pad to avoid address collisions
			bytecode = append(bytecode, make([]byte, 32)...)

			fakeBytecode := base64.StdEncoding.EncodeToString(bytecode)
			resp := map[string]interface{}{
				"hash":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
				"result": fakeBytecode,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
}

// configureMockAlgod sets up a mock algod on the signer and DSA providers.
// Returns a cleanup function that should be deferred.
func configureMockAlgod(t *testing.T, server *Signer) (mockServer *httptest.Server, cleanup func()) {
	t.Helper()
	mockServer = mockAlgodServer()
	server.tealCompilerAlgodURL = mockServer.URL
	server.tealCompilerAlgodToken = ""

	// Configure DSA providers (falcon1024 needs algod for TEAL compilation)
	client, err := algod.MakeClient(mockServer.URL, "")
	if err != nil {
		t.Fatalf("Failed to create mock algod client: %v", err)
	}
	logicsigdsa.ConfigureAlgodClient(client)

	return mockServer, func() { mockServer.Close() }
}

// --- Generate tests ---

func TestAdminGenerateEd25519(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType: "ed25519",
	})

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)

	if resp.Error != "" {
		t.Fatalf("Unexpected error: %s", resp.Error)
	}
	if resp.Address == "" {
		t.Fatal("Expected non-empty address")
	}
	if resp.KeyType != "ed25519" {
		t.Errorf("Expected key_type ed25519, got %s", resp.KeyType)
	}
	// Verify address is a valid 58-char Algorand address
	if len(resp.Address) != 58 {
		t.Errorf("Expected 58-char Algorand address, got %d chars", len(resp.Address))
	}
}

func TestAdminGenerateFalcon1024(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	_, algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType: "falcon1024-v1",
	})

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)

	if resp.Error != "" {
		t.Fatalf("Unexpected error: %s", resp.Error)
	}
	if resp.Address == "" {
		t.Fatal("Expected non-empty address")
	}
	if resp.KeyType != "falcon1024-v1" {
		t.Errorf("Expected key_type falcon1024-v1, got %s", resp.KeyType)
	}
	if len(resp.Address) != 58 {
		t.Errorf("Expected 58-char Algorand address, got %d chars", len(resp.Address))
	}
}

func TestAdminGenerateHashlockV1(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	_, algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	// hashlock-v1 requires: hash, recipient, refund_address, timeout_round
	reqBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType: "hashlock-v1",
		Parameters: map[string]string{
			"hash":           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA256 of empty
			"recipient":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"refund_address": "7777777777777777777777777777777777777777777777777774MSJUVU",
			"timeout_round":  "1000000",
		},
	})

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)

	if resp.Error != "" {
		t.Fatalf("Unexpected error: %s", resp.Error)
	}
	if resp.Address == "" {
		t.Fatal("Expected non-empty address")
	}
	if resp.KeyType != "hashlock-v1" {
		t.Errorf("Expected key_type hashlock-v1, got %s", resp.KeyType)
	}
	// Verify parameters are echoed back
	if resp.Parameters["hash"] == "" {
		t.Error("Expected parameters to include hash")
	}
}

// --- Delete tests ---

func TestAdminDeleteEd25519(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	// First generate a key
	genBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
	genW := httptest.NewRecorder()
	genR := requestWithIdentity(http.MethodPost, "/admin/generate", genBody)
	server.handleAdminGenerate(genW, genR)

	if genW.Code != http.StatusOK {
		t.Fatalf("Generate failed: %d: %s", genW.Code, genW.Body.String())
	}

	var genResp AdminGenerateResponse
	decodeResponse(t, genW, &genResp)
	address := genResp.Address

	// Reload keys so the signer knows about the new key
	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("Failed to reload keys: %v", err)
	}

	// Now delete it
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodDelete, "/admin/keys?address="+address, nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminDeleteResponse
	decodeResponse(t, w, &resp)

	if !resp.Success {
		t.Fatalf("Expected success=true, got error: %s", resp.Error)
	}
}

func TestAdminDeleteFalcon1024(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	_, algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	// Generate a falcon1024-v1 key
	genBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "falcon1024-v1"})
	genW := httptest.NewRecorder()
	genR := requestWithIdentity(http.MethodPost, "/admin/generate", genBody)
	server.handleAdminGenerate(genW, genR)

	if genW.Code != http.StatusOK {
		t.Fatalf("Generate failed: %d: %s", genW.Code, genW.Body.String())
	}

	var genResp AdminGenerateResponse
	decodeResponse(t, genW, &genResp)
	address := genResp.Address

	// Reload keys
	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("Failed to reload keys: %v", err)
	}

	// Delete it
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodDelete, "/admin/keys?address="+address, nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminDeleteResponse
	decodeResponse(t, w, &resp)

	if !resp.Success {
		t.Fatalf("Expected success=true, got error: %s", resp.Error)
	}
}

func TestAdminDeleteHashlockV1(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	_, algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	// Generate a hashlock-v1 key
	genBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType: "hashlock-v1",
		Parameters: map[string]string{
			"hash":           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"recipient":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"refund_address": "7777777777777777777777777777777777777777777777777774MSJUVU",
			"timeout_round":  "1000000",
		},
	})
	genW := httptest.NewRecorder()
	genR := requestWithIdentity(http.MethodPost, "/admin/generate", genBody)
	server.handleAdminGenerate(genW, genR)

	if genW.Code != http.StatusOK {
		t.Fatalf("Generate failed: %d: %s", genW.Code, genW.Body.String())
	}

	var genResp AdminGenerateResponse
	decodeResponse(t, genW, &genResp)
	address := genResp.Address

	// Reload keys
	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("Failed to reload keys: %v", err)
	}

	// Delete it
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodDelete, "/admin/keys?address="+address, nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminDeleteResponse
	decodeResponse(t, w, &resp)

	if !resp.Success {
		t.Fatalf("Expected success=true, got error: %s", resp.Error)
	}
}

// --- Error case tests ---

func TestAdminGenerateMethodNotAllowed(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodGet, "/admin/generate", nil)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestAdminGenerateLockedSigner(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	// Lock the signer
	server.hub.lock()

	reqBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "locked") {
		t.Errorf("Expected 'locked' in error, got %q", resp.Error)
	}
}

func TestAdminGenerateNoIdentity(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
	w := httptest.NewRecorder()
	// No identity in context
	r := httptest.NewRequest(http.MethodPost, "/admin/generate", bytes.NewReader(reqBody))
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestAdminGenerateEmptyKeyType(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{KeyType: ""})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestAdminGenerateInvalidKeyType(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	reqBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "nonexistent-type"})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "invalid key type") {
		t.Errorf("Expected 'invalid key type' in error, got %q", resp.Error)
	}
}

func TestAdminGenerateInvalidJSON(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", []byte("not json"))
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestAdminGenerateHashlockMissingAlgod(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	// No tealCompilerAlgodURL configured
	server.tealCompilerAlgodURL = ""

	reqBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType: "hashlock-v1",
		Parameters: map[string]string{
			"hash":           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"recipient":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"refund_address": "7777777777777777777777777777777777777777777777777774MSJUVU",
			"timeout_round":  "1000000",
		},
	})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "teal_compiler_algod_url") {
		t.Errorf("Expected algod URL error, got %q", resp.Error)
	}
}

func TestAdminGenerateHashlockInvalidParams(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	_, algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	// Missing required params
	reqBody, _ := json.Marshal(AdminGenerateRequest{
		KeyType:    "hashlock-v1",
		Parameters: map[string]string{}, // Missing all required params
	})
	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/generate", reqBody)
	server.handleAdminGenerate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "parameter validation failed") {
		t.Errorf("Expected param validation error, got %q", resp.Error)
	}
}

func TestAdminDeleteMethodNotAllowed(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodPost, "/admin/keys?address=TEST", nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestAdminDeleteLockedSigner(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	server.hub.lock()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodDelete, "/admin/keys?address=TEST", nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}
}

func TestAdminDeleteNoAddress(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodDelete, "/admin/keys", nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}

	var resp AdminDeleteResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "address") {
		t.Errorf("Expected 'address' in error, got %q", resp.Error)
	}
}

func TestAdminDeleteNotFound(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := requestWithIdentity(http.MethodDelete, "/admin/keys?address=NONEXISTENT", nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}

	var resp AdminDeleteResponse
	decodeResponse(t, w, &resp)
	if !strings.Contains(resp.Error, "not found") {
		t.Errorf("Expected 'not found' in error, got %q", resp.Error)
	}
}

func TestAdminDeleteNoIdentity(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/admin/keys?address=TEST", nil)
	server.handleAdminDelete(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

// --- Round-trip tests (generate then delete) ---

func TestAdminGenerateThenDeleteEd25519(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	// Generate
	genBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
	genW := httptest.NewRecorder()
	server.handleAdminGenerate(genW, requestWithIdentity(http.MethodPost, "/admin/generate", genBody))

	if genW.Code != http.StatusOK {
		t.Fatalf("Generate failed: %d: %s", genW.Code, genW.Body.String())
	}
	var genResp AdminGenerateResponse
	decodeResponse(t, genW, &genResp)
	address := genResp.Address

	// Reload keys to populate the in-memory maps
	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("Failed to reload keys: %v", err)
	}

	// Delete
	delW := httptest.NewRecorder()
	server.handleAdminDelete(delW, requestWithIdentity(http.MethodDelete, "/admin/keys?address="+address, nil))

	if delW.Code != http.StatusOK {
		t.Fatalf("Delete failed: %d: %s", delW.Code, delW.Body.String())
	}
	var delResp AdminDeleteResponse
	decodeResponse(t, delW, &delResp)
	if !delResp.Success {
		t.Fatalf("Delete not successful: %s", delResp.Error)
	}

	// Reload keys again to reflect deletion
	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("Failed to reload keys after delete: %v", err)
	}

	// Verify key is gone
	server.keysLock.RLock()
	_, exists := server.keys[auth.DefaultIdentityID][address]
	server.keysLock.RUnlock()
	if exists {
		t.Error("Key should not exist after deletion")
	}
}

func TestAdminGenerateMultipleEd25519(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	addresses := make(map[string]bool)
	for i := 0; i < 3; i++ {
		genBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
		w := httptest.NewRecorder()
		server.handleAdminGenerate(w, requestWithIdentity(http.MethodPost, "/admin/generate", genBody))

		if w.Code != http.StatusOK {
			t.Fatalf("Generate %d failed: %d: %s", i, w.Code, w.Body.String())
		}
		var resp AdminGenerateResponse
		decodeResponse(t, w, &resp)

		if addresses[resp.Address] {
			t.Errorf("Duplicate address generated: %s", resp.Address)
		}
		addresses[resp.Address] = true
	}

	if len(addresses) != 3 {
		t.Errorf("Expected 3 unique addresses, got %d", len(addresses))
	}
}

// reloadKeysForTest rescans the keys directory to update in-memory maps.
// This simulates what the file watcher does in production.
func reloadKeysForTest(server *Signer) error {
	// We need a passphrase to call Scan. Set up the encryptionPassphrase.
	if server.encryptionPassphrase == nil {
		server.encryptionPassphrase = crypto.NewSecureStringFromBytes(testPassphrase)
	}

	// Create a key session if not present
	if server.keySession == nil {
		server.keySession = keystore.NewKeySession(server.keyStore)
	}

	// Use the same reload path as production
	server.passphraseLock.Lock()
	defer server.passphraseLock.Unlock()

	if err := server.keyStore.Scan(testPassphrase); err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	newKeysMap := server.keyStore.GetCache()
	newKeyTypes := server.keyStore.GetKeyTypes()
	newLsigSizes := server.keyStore.GetLsigSizes()

	server.keysLock.Lock()
	server.keys[auth.DefaultIdentityID] = newKeysMap
	server.keyTypes[auth.DefaultIdentityID] = newKeyTypes
	server.keyLsigSizes[auth.DefaultIdentityID] = newLsigSizes
	server.keysLock.Unlock()

	return nil
}
