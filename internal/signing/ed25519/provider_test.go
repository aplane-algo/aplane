// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"

	"github.com/aplane-algo/aplane/internal/signing"
)

func init() {
	// Register Ed25519 provider for tests
	RegisterProvider()
}

// TestEd25519Provider_Family verifies it returns "ed25519"
func TestEd25519Provider_Family(t *testing.T) {
	provider := &Ed25519Provider{}
	if provider.Family() != "ed25519" {
		t.Errorf("Expected family 'ed25519', got '%s'", provider.Family())
	}
}

// generateValidEd25519Keys creates a valid Ed25519 key pair for testing
func generateValidEd25519Keys(t *testing.T) (publicKey, privateKey []byte) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Algorand SDK expects 64-byte private key (seed + public key)
	return pub, priv
}

// createKeyJSON creates the JSON format used for Ed25519 keys
func createKeyJSON(t *testing.T, keyType, pubHex, privHex string) []byte {
	t.Helper()

	data := Ed25519Keys{
		Type:          keyType,
		PublicKeyHex:  pubHex,
		PrivateKeyHex: privHex,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Failed to marshal key JSON: %v", err)
	}
	return jsonBytes
}

// TestEd25519Provider_LoadKeysFromData_Valid tests loading a valid 64-byte key
func TestEd25519Provider_LoadKeysFromData_Valid(t *testing.T) {
	provider := &Ed25519Provider{}
	pubKey, privKey := generateValidEd25519Keys(t)

	keyJSON := createKeyJSON(t, "ed25519",
		hex.EncodeToString(pubKey),
		hex.EncodeToString(privKey),
	)

	keyMaterial, err := provider.LoadKeysFromData(keyJSON)
	if err != nil {
		t.Fatalf("LoadKeysFromData failed: %v", err)
	}
	defer provider.ZeroKey(keyMaterial)

	// Verify key material
	if keyMaterial.Type != "ed25519" {
		t.Errorf("Expected type 'ed25519', got '%s'", keyMaterial.Type)
	}

	account, ok := keyMaterial.Value.(algocrypto.Account)
	if !ok {
		t.Fatal("Key value should be crypto.Account")
	}

	// Verify public key matches
	if !bytes.Equal(account.PublicKey[:], pubKey) {
		t.Error("Public key doesn't match")
	}
}

// TestEd25519Provider_LoadKeysFromData_InvalidJSON tests bad JSON handling
func TestEd25519Provider_LoadKeysFromData_InvalidJSON(t *testing.T) {
	provider := &Ed25519Provider{}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "invalid JSON syntax",
			data: []byte("{invalid json"),
		},
		{
			name: "empty object",
			data: []byte("{}"),
		},
		{
			name: "null",
			data: []byte("null"),
		},
		{
			name: "array instead of object",
			data: []byte(`["not", "an", "object"]`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := provider.LoadKeysFromData(tt.data)
			if err == nil {
				t.Error("Expected error for invalid JSON")
			}
		})
	}
}

// TestEd25519Provider_LoadKeysFromData_InvalidHex tests bad hex handling
func TestEd25519Provider_LoadKeysFromData_InvalidHex(t *testing.T) {
	provider := &Ed25519Provider{}

	tests := []struct {
		name    string
		privHex string
	}{
		{
			name:    "invalid hex characters",
			privHex: "not-valid-hex!!!",
		},
		{
			name:    "odd length hex",
			privHex: "abc",
		},
		{
			name:    "empty hex",
			privHex: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyJSON := createKeyJSON(t, "ed25519", "0000", tt.privHex)
			_, err := provider.LoadKeysFromData(keyJSON)
			if err == nil {
				t.Error("Expected error for invalid hex")
			}
		})
	}
}

// TestEd25519Provider_LoadKeysFromData_InvalidLength tests wrong key length
func TestEd25519Provider_LoadKeysFromData_InvalidLength(t *testing.T) {
	provider := &Ed25519Provider{}

	tests := []struct {
		name      string
		keyLength int
	}{
		{
			name:      "32 bytes (too short)",
			keyLength: 32,
		},
		{
			name:      "128 bytes (too long)",
			keyLength: 128,
		},
		{
			name:      "1 byte",
			keyLength: 1,
		},
		{
			name:      "63 bytes (off by one)",
			keyLength: 63,
		},
		{
			name:      "65 bytes (off by one)",
			keyLength: 65,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create key of wrong length
			wrongKey := make([]byte, tt.keyLength)
			_, _ = rand.Read(wrongKey)

			keyJSON := createKeyJSON(t, "ed25519",
				hex.EncodeToString(make([]byte, 32)),
				hex.EncodeToString(wrongKey),
			)

			_, err := provider.LoadKeysFromData(keyJSON)
			if err == nil {
				t.Errorf("Expected error for %d-byte key", tt.keyLength)
			}
			if err != nil && !contains(err.Error(), "invalid Ed25519 private key length") {
				t.Errorf("Error should mention invalid length: %v", err)
			}
		})
	}
}

// TestEd25519Provider_SignMessage verifies signing and SDK verification
func TestEd25519Provider_SignMessage(t *testing.T) {
	provider := &Ed25519Provider{}
	pubKey, privKey := generateValidEd25519Keys(t)

	keyJSON := createKeyJSON(t, "ed25519",
		hex.EncodeToString(pubKey),
		hex.EncodeToString(privKey),
	)

	keyMaterial, err := provider.LoadKeysFromData(keyJSON)
	if err != nil {
		t.Fatalf("LoadKeysFromData failed: %v", err)
	}
	defer provider.ZeroKey(keyMaterial)

	// Sign a message
	message := []byte("test message to sign")
	signature, err := provider.SignMessage(keyMaterial, message)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	// Verify signature length (Ed25519 signatures are 64 bytes)
	if len(signature) != 64 {
		t.Errorf("Expected 64-byte signature, got %d bytes", len(signature))
	}

	// Verify using standard Ed25519
	if !ed25519.Verify(pubKey, message, signature) {
		t.Error("Signature verification failed")
	}
}

// TestEd25519Provider_SignMessage_DifferentMessages verifies different messages get different sigs
func TestEd25519Provider_SignMessage_DifferentMessages(t *testing.T) {
	provider := &Ed25519Provider{}
	pubKey, privKey := generateValidEd25519Keys(t)

	keyJSON := createKeyJSON(t, "ed25519",
		hex.EncodeToString(pubKey),
		hex.EncodeToString(privKey),
	)

	keyMaterial, err := provider.LoadKeysFromData(keyJSON)
	if err != nil {
		t.Fatalf("LoadKeysFromData failed: %v", err)
	}
	defer provider.ZeroKey(keyMaterial)

	message1 := []byte("first message")
	message2 := []byte("second message")

	sig1, err := provider.SignMessage(keyMaterial, message1)
	if err != nil {
		t.Fatalf("SignMessage 1 failed: %v", err)
	}

	sig2, err := provider.SignMessage(keyMaterial, message2)
	if err != nil {
		t.Fatalf("SignMessage 2 failed: %v", err)
	}

	// Different messages should produce different signatures
	if bytes.Equal(sig1, sig2) {
		t.Error("Different messages should produce different signatures")
	}

	// Both should verify correctly
	if !ed25519.Verify(pubKey, message1, sig1) {
		t.Error("Signature 1 verification failed")
	}
	if !ed25519.Verify(pubKey, message2, sig2) {
		t.Error("Signature 2 verification failed")
	}
}

// TestEd25519Provider_SignMessage_EmptyMessage tests signing empty message
func TestEd25519Provider_SignMessage_EmptyMessage(t *testing.T) {
	provider := &Ed25519Provider{}
	pubKey, privKey := generateValidEd25519Keys(t)

	keyJSON := createKeyJSON(t, "ed25519",
		hex.EncodeToString(pubKey),
		hex.EncodeToString(privKey),
	)

	keyMaterial, err := provider.LoadKeysFromData(keyJSON)
	if err != nil {
		t.Fatalf("LoadKeysFromData failed: %v", err)
	}
	defer provider.ZeroKey(keyMaterial)

	// Empty message should still work
	emptyMessage := []byte{}
	signature, err := provider.SignMessage(keyMaterial, emptyMessage)
	if err != nil {
		t.Fatalf("SignMessage failed for empty message: %v", err)
	}

	if !ed25519.Verify(pubKey, emptyMessage, signature) {
		t.Error("Empty message signature verification failed")
	}
}

// TestEd25519Provider_SignMessage_NilKey tests signing with nil key
func TestEd25519Provider_SignMessage_NilKey(t *testing.T) {
	provider := &Ed25519Provider{}

	_, err := provider.SignMessage(nil, []byte("message"))
	if err == nil {
		t.Error("Expected error for nil key")
	}
}

// TestEd25519Provider_SignMessage_WrongKeyType tests signing with wrong key type
func TestEd25519Provider_SignMessage_WrongKeyType(t *testing.T) {
	provider := &Ed25519Provider{}

	// Create key material with wrong type
	keyMaterial := &signing.KeyMaterial{
		Type:  "falcon1024", // Wrong type
		Value: algocrypto.Account{},
	}

	_, err := provider.SignMessage(keyMaterial, []byte("message"))
	if err == nil {
		t.Error("Expected error for wrong key type")
	}
	if !contains(err.Error(), "mismatch") {
		t.Errorf("Error should mention type mismatch: %v", err)
	}
}

// TestEd25519Provider_SignMessage_WrongValueType tests signing with wrong value type
func TestEd25519Provider_SignMessage_WrongValueType(t *testing.T) {
	provider := &Ed25519Provider{}

	// Create key material with correct type but wrong value type
	keyMaterial := &signing.KeyMaterial{
		Type:  "ed25519",
		Value: "not-an-account", // Wrong value type
	}

	_, err := provider.SignMessage(keyMaterial, []byte("message"))
	if err == nil {
		t.Error("Expected error for wrong value type")
	}
	if !contains(err.Error(), "invalid key value") {
		t.Errorf("Error should mention invalid key value: %v", err)
	}
}

// TestEd25519Provider_ZeroKey verifies secure cleanup
func TestEd25519Provider_ZeroKey(t *testing.T) {
	provider := &Ed25519Provider{}
	_, privKey := generateValidEd25519Keys(t)

	keyJSON := createKeyJSON(t, "ed25519",
		hex.EncodeToString(make([]byte, 32)),
		hex.EncodeToString(privKey),
	)

	keyMaterial, err := provider.LoadKeysFromData(keyJSON)
	if err != nil {
		t.Fatalf("LoadKeysFromData failed: %v", err)
	}

	account, ok := keyMaterial.Value.(algocrypto.Account)
	if !ok {
		t.Fatal("Expected crypto.Account")
	}

	// Copy key bytes before zeroing for verification
	originalPrivKey := make([]byte, len(account.PrivateKey))
	copy(originalPrivKey, account.PrivateKey[:])

	// Zero the key
	provider.ZeroKey(keyMaterial)

	// Verify key material fields are cleared
	if keyMaterial.Type != "" {
		t.Error("Type should be cleared after ZeroKey")
	}
	if keyMaterial.Value != nil {
		t.Error("Value should be nil after ZeroKey")
	}
}

// TestEd25519Provider_ZeroKey_Nil verifies nil key doesn't panic
func TestEd25519Provider_ZeroKey_Nil(t *testing.T) {
	provider := &Ed25519Provider{}

	// Should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ZeroKey panicked on nil: %v", r)
		}
	}()

	provider.ZeroKey(nil)
}

// TestEd25519Provider_ZeroKey_WrongValueType verifies wrong value type doesn't panic
func TestEd25519Provider_ZeroKey_WrongValueType(t *testing.T) {
	provider := &Ed25519Provider{}

	keyMaterial := &signing.KeyMaterial{
		Type:  "ed25519",
		Value: "not-an-account",
	}

	// Should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ZeroKey panicked on wrong value type: %v", r)
		}
	}()

	provider.ZeroKey(keyMaterial)

	// Should still clear the wrapper
	if keyMaterial.Type != "" || keyMaterial.Value != nil {
		t.Error("Wrapper should still be cleared")
	}
}

// TestEd25519Provider_DetectKeyType tests key type detection
func TestEd25519Provider_DetectKeyType(t *testing.T) {
	provider := &Ed25519Provider{}

	tests := []struct {
		name       string
		keyData    []byte
		passphrase string
		expected   bool
	}{
		{
			name:       "valid ed25519 unencrypted",
			keyData:    []byte(`{"key_type":"ed25519","public_key":"0000","private_key":"0000"}`),
			passphrase: "",
			expected:   true,
		},
		{
			name:       "falcon key",
			keyData:    []byte(`{"key_type":"falcon1024","public_key":"0000","private_key":"0000"}`),
			passphrase: "",
			expected:   false,
		},
		{
			name:       "invalid JSON",
			keyData:    []byte("{invalid"),
			passphrase: "",
			expected:   false,
		},
		{
			name:       "encrypted data with passphrase",
			keyData:    []byte(`{"key_type":"ed25519"}`),
			passphrase: "some-passphrase",
			expected:   false, // Detection returns false when passphrase is provided
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.DetectKeyType(tt.keyData, tt.passphrase)
			if result != tt.expected {
				t.Errorf("DetectKeyType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestEd25519Provider_Registration verifies provider is registered
func TestEd25519Provider_Registration(t *testing.T) {
	// The provider should be auto-registered via init()
	provider := signing.GetProvider("ed25519")
	if provider == nil {
		t.Fatal("Ed25519 provider should be registered")
	}

	if provider.Family() != "ed25519" {
		t.Errorf("Registered provider has wrong family: %s", provider.Family())
	}
}

// TestEd25519Provider_SignMessage_Deterministic verifies same key+message = same signature
func TestEd25519Provider_SignMessage_Deterministic(t *testing.T) {
	provider := &Ed25519Provider{}
	pubKey, privKey := generateValidEd25519Keys(t)

	keyJSON := createKeyJSON(t, "ed25519",
		hex.EncodeToString(pubKey),
		hex.EncodeToString(privKey),
	)

	keyMaterial, err := provider.LoadKeysFromData(keyJSON)
	if err != nil {
		t.Fatalf("LoadKeysFromData failed: %v", err)
	}
	defer provider.ZeroKey(keyMaterial)

	message := []byte("deterministic test message")

	sig1, _ := provider.SignMessage(keyMaterial, message)
	sig2, _ := provider.SignMessage(keyMaterial, message)

	// Ed25519 signatures are deterministic
	if !bytes.Equal(sig1, sig2) {
		t.Error("Ed25519 signatures should be deterministic for same key+message")
	}
}

// Helper function
func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}
