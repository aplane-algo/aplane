// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package testutil provides reusable test infrastructure and utilities.
package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// TestKey represents a generated test key pair
type TestKey struct {
	Address       string
	PublicKey     []byte
	PrivateKey    []byte
	PublicKeyHex  string
	PrivateKeyHex string
}

// testKeyPair is the JSON structure for key files
type testKeyPair struct {
	KeyType       string `json:"key_type"`
	PublicKeyHex  string `json:"public_key"`
	PrivateKeyHex string `json:"private_key"`
}

// GenerateTestEd25519Key generates a deterministic Ed25519 key pair for testing.
// The seed parameter allows generating different keys in a reproducible way.
func GenerateTestEd25519Key(t *testing.T, seed int) *TestKey {
	t.Helper()

	// Generate truly random key for testing
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Derive Algorand address from public key
	var pk [32]byte
	copy(pk[:], pubKey)
	address := types.Address(pk).String()

	return &TestKey{
		Address:       address,
		PublicKey:     pubKey,
		PrivateKey:    privKey,
		PublicKeyHex:  hex.EncodeToString(pubKey),
		PrivateKeyHex: hex.EncodeToString(privKey),
	}
}

// SetupTestKeysDir creates a temporary keys directory and configures the global keystore path.
// Returns the identity-scoped keys directory path (store/users/default/keys/) and a cleanup function.
func SetupTestKeysDir(t *testing.T) (keysDir string, cleanup func()) {
	t.Helper()

	tmpDir := t.TempDir()
	// Create identity-scoped directory: tmpDir/users/default/keys/
	keysDir = filepath.Join(tmpDir, "users", "default", "keys")
	if err := os.MkdirAll(keysDir, 0750); err != nil {
		t.Fatalf("Failed to create test keys dir: %v", err)
	}

	// Save old keystore path and set new one (tmpDir is the keystore root)
	oldPath := utilkeys.KeystorePath()
	utilkeys.SetKeystorePath(tmpDir)

	cleanup = func() {
		utilkeys.SetKeystorePath(oldPath)
	}

	return keysDir, cleanup
}

// WriteTestKeyFile creates a test key file in the specified directory.
// If masterKey is non-empty (must be exactly 32 bytes), the file will be encrypted.
// Returns the file path.
func WriteTestKeyFile(t *testing.T, keysDir string, key *TestKey, masterKey []byte) string {
	t.Helper()

	keyPair := testKeyPair{
		KeyType:       "ed25519",
		PublicKeyHex:  key.PublicKeyHex,
		PrivateKeyHex: key.PrivateKeyHex,
	}

	keyJSON, err := json.MarshalIndent(keyPair, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}
	defer crypto.ZeroBytes(keyJSON)

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

	// Use first 8 chars of address as filename
	filename := key.Address
	if len(filename) > 8 {
		filename = filename[:8]
	}
	filePath := filepath.Join(keysDir, filename+".key")

	if err := os.WriteFile(filePath, dataToWrite, 0600); err != nil {
		t.Fatalf("Failed to write test key file: %v", err)
	}

	return filePath
}

// ValidTestAddress generates a valid Algorand address for testing.
// The index allows generating different addresses.
func ValidTestAddress(index int) string {
	// Generate a deterministic address based on index
	var pk [32]byte
	pk[0] = byte(index)
	pk[1] = byte(index >> 8)
	return types.Address(pk).String()
}

// MustDecodeAddress decodes an Algorand address string, failing the test on error.
func MustDecodeAddress(t *testing.T, addr string) types.Address {
	t.Helper()

	decoded, err := types.DecodeAddress(addr)
	if err != nil {
		t.Fatalf("Failed to decode address %s: %v", addr, err)
	}
	return decoded
}

// TempFile creates a temporary file with the given content, returning the path.
// The file is automatically cleaned up when the test completes.
func TempFile(t *testing.T, content []byte) string {
	t.Helper()

	tmpFile, err := os.CreateTemp(t.TempDir(), "testfile-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		t.Fatalf("Failed to write temp file: %v", err)
	}

	_ = tmpFile.Close()
	return tmpFile.Name()
}

// AssertError checks that an error matches expected criteria.
func AssertError(t *testing.T, err error, shouldError bool, msgContains string) {
	t.Helper()

	if shouldError {
		if err == nil {
			t.Error("Expected an error but got nil")
			return
		}
		if msgContains != "" && err.Error() != msgContains {
			// Check if it contains the substring
			if len(err.Error()) < len(msgContains) || err.Error()[:len(msgContains)] != msgContains {
				// Use simple contains check
				found := false
				for i := 0; i <= len(err.Error())-len(msgContains); i++ {
					if err.Error()[i:i+len(msgContains)] == msgContains {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Error message %q should contain %q", err.Error(), msgContains)
				}
			}
		}
	} else {
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	}
}
