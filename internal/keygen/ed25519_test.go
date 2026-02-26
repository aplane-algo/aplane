// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keygen

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	algocrypto "github.com/aplane-algo/aplane/internal/crypto"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// testMasterKey is a 32-byte key for testing (AES-256 requires exactly 32 bytes)
var testMasterKey = []byte("test-master-key-32-bytes-long!!!")

// setupTestKeystore sets up a temp directory and configures the keystore path for testing
func setupTestKeystore(t *testing.T) (cleanup func()) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	// Set keystore path to "." so KeysDir("default") returns "./users/default/keys"
	utilkeys.SetKeystorePath(".")
	return func() {
		_ = os.Chdir(oldDir)
	}
}

// TestEd25519GeneratorKeyType verifies the key type identifier
func TestEd25519GeneratorKeyType(t *testing.T) {
	gen := &Ed25519Generator{}
	if gen.Family() != "ed25519" {
		t.Errorf("KeyType() = %q, want %q", gen.Family(), "ed25519")
	}
}

// TestGenerateFromSeed verifies deterministic key generation from seed
func TestGenerateFromSeed(t *testing.T) {
	cleanup := setupTestKeystore(t)
	defer cleanup()

	gen := &Ed25519Generator{}

	// Generate a test seed (32 bytes)
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}

	masterKey := testMasterKey

	// Generate key from seed
	result, err := gen.GenerateFromSeed(seed, masterKey, "ed25519", nil)
	if err != nil {
		t.Fatalf("GenerateFromSeed failed: %v", err)
	}

	// Verify result fields
	if result.Address == "" {
		t.Error("Address should not be empty")
	}
	if result.PublicKeyHex == "" {
		t.Error("PublicKeyHex should not be empty")
	}
	if result.Mnemonic != "" {
		t.Error("Mnemonic should be empty when generating from seed")
	}
	if result.KeyFiles == nil {
		t.Fatal("KeyFiles should not be nil")
	}
	if result.KeyFiles.PrivateFile == "" {
		t.Error("PrivateFile path should not be empty")
	}

	// Verify key file was created
	if _, err := os.Stat(result.KeyFiles.PrivateFile); os.IsNotExist(err) {
		t.Errorf("Private key file not created: %s", result.KeyFiles.PrivateFile)
	}

	// Verify determinism: same seed should produce same keys
	result2, err := gen.GenerateFromSeed(seed, masterKey, "ed25519", nil)
	if err != nil {
		t.Fatalf("Second GenerateFromSeed failed: %v", err)
	}

	if result.Address != result2.Address {
		t.Error("Same seed should produce same address")
	}
	if result.PublicKeyHex != result2.PublicKeyHex {
		t.Error("Same seed should produce same public key")
	}

	// Verify different seed produces different keys
	differentSeed := make([]byte, ed25519.SeedSize)
	for i := range differentSeed {
		differentSeed[i] = byte(255 - i)
	}

	result3, err := gen.GenerateFromSeed(differentSeed, masterKey, "ed25519", nil)
	if err != nil {
		t.Fatalf("Third GenerateFromSeed failed: %v", err)
	}

	if result.Address == result3.Address {
		t.Error("Different seeds should produce different addresses")
	}
}

// TestGenerateFromSeedInvalidSize verifies error handling for invalid seed size
func TestGenerateFromSeedInvalidSize(t *testing.T) {
	cleanup := setupTestKeystore(t)
	defer cleanup()

	gen := &Ed25519Generator{}

	tests := []struct {
		name     string
		seedSize int
	}{
		{"too short", 16},
		{"too long", 64},
		{"empty", 0},
		{"slightly wrong", 31},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := make([]byte, tt.seedSize)
			_, err := gen.GenerateFromSeed(seed, testMasterKey, "ed25519", nil)
			if err == nil {
				t.Errorf("Expected error for seed size %d, got nil", tt.seedSize)
			}
			if !strings.Contains(err.Error(), "invalid seed size") {
				t.Errorf("Error should mention invalid seed size, got: %v", err)
			}
		})
	}
}

// TestGenerateFromMnemonic verifies key generation from Algorand mnemonic
func TestGenerateFromMnemonic(t *testing.T) {
	cleanup := setupTestKeystore(t)
	defer cleanup()

	gen := &Ed25519Generator{}

	// Use a well-known test mnemonic (25 words)
	// This is Algorand's standard test mnemonic
	testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest"

	masterKey := testMasterKey

	// Generate key from mnemonic
	result, err := gen.GenerateFromMnemonic(testMnemonic, masterKey, "ed25519", nil)
	if err != nil {
		t.Fatalf("GenerateFromMnemonic failed: %v", err)
	}

	// Verify result fields
	if result.Address == "" {
		t.Error("Address should not be empty")
	}
	if result.PublicKeyHex == "" {
		t.Error("PublicKeyHex should not be empty")
	}
	if result.Mnemonic != testMnemonic {
		t.Errorf("Mnemonic in result = %q, want %q", result.Mnemonic, testMnemonic)
	}

	// Verify determinism: same mnemonic should produce same address
	result2, err := gen.GenerateFromMnemonic(testMnemonic, masterKey, "ed25519", nil)
	if err != nil {
		t.Fatalf("Second GenerateFromMnemonic failed: %v", err)
	}

	if result.Address != result2.Address {
		t.Error("Same mnemonic should produce same address")
	}

	// Verify the generated address matches Algorand SDK expectation
	privKey, err := mnemonic.ToPrivateKey(testMnemonic)
	if err != nil {
		t.Fatalf("Failed to derive private key for verification: %v", err)
	}

	// Derive expected address
	account, err := crypto.AccountFromPrivateKey(privKey)
	if err != nil {
		t.Fatalf("Failed to derive account: %v", err)
	}

	if result.Address != account.Address.String() {
		t.Errorf("Generated address %s doesn't match expected %s", result.Address, account.Address.String())
	}
}

// TestGenerateFromMnemonicInvalid verifies error handling for invalid mnemonics
func TestGenerateFromMnemonicInvalid(t *testing.T) {
	cleanup := setupTestKeystore(t)
	defer cleanup()

	gen := &Ed25519Generator{}

	tests := []struct {
		name     string
		mnemonic string
	}{
		{"empty", ""},
		{"too few words", "abandon abandon abandon"},
		{"invalid word", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid"},
		{"wrong checksum", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := gen.GenerateFromMnemonic(tt.mnemonic, testMasterKey, "ed25519", nil)
			if err == nil {
				t.Error("Expected error for invalid mnemonic, got nil")
			}
		})
	}
}

// TestGenerateRandom verifies random key generation
func TestGenerateRandom(t *testing.T) {
	cleanup := setupTestKeystore(t)
	defer cleanup()

	gen := &Ed25519Generator{}
	masterKey := testMasterKey

	// Generate random key
	result, err := gen.GenerateRandom(masterKey, "ed25519", nil)
	if err != nil {
		t.Fatalf("GenerateRandom failed: %v", err)
	}

	// Verify result fields
	if result.Address == "" {
		t.Error("Address should not be empty")
	}
	if result.PublicKeyHex == "" {
		t.Error("PublicKeyHex should not be empty")
	}
	if result.Mnemonic == "" {
		t.Error("Mnemonic should not be empty for random generation")
	}
	if result.KeyFiles == nil {
		t.Fatal("KeyFiles should not be nil")
	}

	// Verify mnemonic has 25 words (Algorand standard)
	words := strings.Fields(result.Mnemonic)
	if len(words) != 25 {
		t.Errorf("Mnemonic should have 25 words, got %d", len(words))
	}

	// Verify we can derive the same key from the mnemonic
	result2, err := gen.GenerateFromMnemonic(result.Mnemonic, masterKey, "ed25519", nil)
	if err != nil {
		t.Fatalf("Failed to regenerate from mnemonic: %v", err)
	}

	if result.Address != result2.Address {
		t.Error("Regenerated address from mnemonic doesn't match original")
	}
	if result.PublicKeyHex != result2.PublicKeyHex {
		t.Error("Regenerated public key from mnemonic doesn't match original")
	}

	// Verify randomness: generate another key and ensure it's different
	result3, err := gen.GenerateRandom(masterKey, "ed25519", nil)
	if err != nil {
		t.Fatalf("Second GenerateRandom failed: %v", err)
	}

	if result.Address == result3.Address {
		t.Error("Two random generations should produce different addresses")
	}
	if result.Mnemonic == result3.Mnemonic {
		t.Error("Two random generations should produce different mnemonics")
	}
}

// TestSaveEd25519KeysWithEncryption verifies key file saving with encryption
func TestSaveEd25519KeysWithEncryption(t *testing.T) {
	cleanup := setupTestKeystore(t)
	defer cleanup()

	// Generate test key pair
	account := crypto.GenerateAccount()
	masterKey := testMasterKey

	// Save keys
	keyFiles, err := saveEd25519Keys(
		account.PublicKey,
		account.PrivateKey,
		account.Address.String(),
		masterKey,
	)
	if err != nil {
		t.Fatalf("saveEd25519Keys failed: %v", err)
	}

	// Verify key file exists
	if _, err := os.Stat(keyFiles.PrivateFile); os.IsNotExist(err) {
		t.Errorf("Private key file not created: %s", keyFiles.PrivateFile)
	}

	// Read and verify encrypted file
	encryptedData, err := os.ReadFile(keyFiles.PrivateFile)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	// Should be encrypted (valid JSON with version field)
	if !algocrypto.IsEncrypted(encryptedData) {
		t.Error("Key file should be encrypted")
	}

	// Decrypt and verify contents (using master key encryption)
	decrypted, err := algocrypto.DecryptWithMasterKey(encryptedData, masterKey)
	if err != nil {
		t.Fatalf("Failed to decrypt key file: %v", err)
	}

	// Parse key pair
	var keyPair utilkeys.KeyPair
	if err := json.Unmarshal(decrypted, &keyPair); err != nil {
		t.Fatalf("Failed to parse decrypted key: %v", err)
	}

	// Verify key type
	if keyPair.KeyType != "ed25519" {
		t.Errorf("Key type = %q, want %q", keyPair.KeyType, "ed25519")
	}

	// Verify public key matches
	expectedPubKeyHex := hex.EncodeToString(account.PublicKey)
	if keyPair.PublicKeyHex != expectedPubKeyHex {
		t.Error("Stored public key doesn't match original")
	}

	// Verify private key matches
	expectedPrivKeyHex := hex.EncodeToString(account.PrivateKey)
	if keyPair.PrivateKeyHex != expectedPrivKeyHex {
		t.Error("Stored private key doesn't match original")
	}
}

// TestSaveEd25519KeysWithoutEncryption verifies unencrypted key saving
func TestSaveEd25519KeysWithoutEncryption(t *testing.T) {
	cleanup := setupTestKeystore(t)
	defer cleanup()

	// Generate test key pair
	account := crypto.GenerateAccount()

	// Save keys without passphrase (unencrypted)
	keyFiles, err := saveEd25519Keys(
		account.PublicKey,
		account.PrivateKey,
		account.Address.String(),
		nil, // No passphrase
	)
	if err != nil {
		t.Fatalf("saveEd25519Keys failed: %v", err)
	}

	// Read key file
	data, err := os.ReadFile(keyFiles.PrivateFile)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	// Should NOT be encrypted (plain JSON)
	if algocrypto.IsEncrypted(data) {
		t.Error("Key file should not be encrypted when passphrase is empty")
	}

	// Parse directly as JSON
	var keyPair utilkeys.KeyPair
	if err := json.Unmarshal(data, &keyPair); err != nil {
		t.Fatalf("Failed to parse key file as plain JSON: %v", err)
	}

	// Verify contents
	if keyPair.KeyType != "ed25519" {
		t.Errorf("Key type = %q, want %q", keyPair.KeyType, "ed25519")
	}
}

// TestKeyFilePermissions verifies proper file permissions
func TestKeyFilePermissions(t *testing.T) {
	cleanup := setupTestKeystore(t)
	defer cleanup()

	gen := &Ed25519Generator{}

	// Generate random key
	result, err := gen.GenerateRandom(testMasterKey, "ed25519", nil)
	if err != nil {
		t.Fatalf("GenerateRandom failed: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(result.KeyFiles.PrivateFile)
	if err != nil {
		t.Fatalf("Failed to stat key file: %v", err)
	}

	// Should be 0660 (readable/writable by owner and group)
	mode := info.Mode().Perm()
	expectedMode := os.FileMode(0660)
	if mode != expectedMode {
		t.Errorf("Key file permissions = %o, want %o", mode, expectedMode)
	}
}

// TestKeysDirectoryCreation verifies keys directory is created if missing
func TestKeysDirectoryCreation(t *testing.T) {
	cleanup := setupTestKeystore(t)
	defer cleanup()

	gen := &Ed25519Generator{}

	// Ensure users directory doesn't exist
	_ = os.RemoveAll("users")

	// Generate key (should create directory)
	result, err := gen.GenerateRandom(testMasterKey, "ed25519", nil)
	if err != nil {
		t.Fatalf("GenerateRandom failed: %v", err)
	}

	// Verify identity-scoped keys directory was created
	info, err := os.Stat(filepath.Join("users", "default", "keys"))
	if err != nil {
		t.Fatal("users/default/keys directory was not created")
	}

	if !info.IsDir() {
		t.Error("users/default/keys should be a directory")
	}

	// Verify key file is in the identity-scoped keys directory
	if !strings.HasPrefix(result.KeyFiles.PrivateFile, filepath.Join("users", "default", "keys")+string(filepath.Separator)) {
		t.Errorf("Key file should be in users/default/keys/ directory, got %s", result.KeyFiles.PrivateFile)
	}
}

// TestAddressFormat verifies generated addresses are valid Algorand format
func TestAddressFormat(t *testing.T) {
	cleanup := setupTestKeystore(t)
	defer cleanup()

	gen := &Ed25519Generator{}

	result, err := gen.GenerateRandom(testMasterKey, "ed25519", nil)
	if err != nil {
		t.Fatalf("GenerateRandom failed: %v", err)
	}

	// Algorand addresses are 58 characters, base32 encoded
	if len(result.Address) != 58 {
		t.Errorf("Address length = %d, want 58", len(result.Address))
	}

	// Should be decodable as Algorand address
	_, err = types.DecodeAddress(result.Address)
	if err != nil {
		t.Errorf("Generated address is not valid Algorand address: %v", err)
	}

	// Verify filename matches address (identity-scoped)
	expectedFile := filepath.Join("users", "default", "keys", result.Address+".key")
	if result.KeyFiles.PrivateFile != expectedFile {
		t.Errorf("Private file path = %s, want %s", result.KeyFiles.PrivateFile, expectedFile)
	}
}

// TestPublicKeyHexFormat verifies public key hex encoding
func TestPublicKeyHexFormat(t *testing.T) {
	cleanup := setupTestKeystore(t)
	defer cleanup()

	gen := &Ed25519Generator{}

	result, err := gen.GenerateRandom(testMasterKey, "ed25519", nil)
	if err != nil {
		t.Fatalf("GenerateRandom failed: %v", err)
	}

	// Public key should be hex encoded (64 hex chars = 32 bytes)
	if len(result.PublicKeyHex) != 64 {
		t.Errorf("PublicKeyHex length = %d, want 64", len(result.PublicKeyHex))
	}

	// Should be valid hex
	pubKeyBytes, err := hex.DecodeString(result.PublicKeyHex)
	if err != nil {
		t.Errorf("PublicKeyHex is not valid hex: %v", err)
	}

	// Should be 32 bytes (Ed25519 public key size)
	if len(pubKeyBytes) != 32 {
		t.Errorf("Decoded public key length = %d, want 32", len(pubKeyBytes))
	}
}
