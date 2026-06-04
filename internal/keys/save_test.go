// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestSaveKeyFile_Encrypted(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	address := "TESTADDR123"

	keyPair := &KeyPair{
		Category:      CategoryEd25519,
		KeyType:       "ed25519",
		PublicKeyHex:  "aabbccdd",
		PrivateKeyHex: "11223344",
	}

	result, err := SaveKeyFile(paths, keyPair, "default", address, masterKey)
	if err != nil {
		t.Fatalf("SaveKeyFile() error = %v", err)
	}

	if result.Address != address {
		t.Errorf("Address = %q, want %q", result.Address, address)
	}
	if result.PrivateFile == "" {
		t.Error("PrivateFile should not be empty")
	}

	// Verify file exists and is encrypted
	data, err := os.ReadFile(result.PrivateFile)
	if err != nil {
		t.Fatalf("Failed to read written file: %v", err)
	}
	if !crypto.IsEncrypted(data) {
		t.Error("file should be encrypted when masterKey is provided")
	}
	assertKeyFileMode(t, result.PrivateFile, fsutil.StoreFilePerm)

	// Verify round-trip: decrypt and check content
	decrypted, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	defer crypto.ZeroBytes(decrypted)

	var roundTripped KeyPair
	if err := json.Unmarshal(decrypted, &roundTripped); err != nil {
		t.Fatalf("Failed to unmarshal decrypted: %v", err)
	}
	if roundTripped.KeyType != "ed25519" {
		t.Errorf("KeyType = %q, want %q", roundTripped.KeyType, "ed25519")
	}
	if roundTripped.PublicKeyHex != "aabbccdd" {
		t.Errorf("PublicKeyHex = %q, want %q", roundTripped.PublicKeyHex, "aabbccdd")
	}
	if _, err := os.Stat(ComponentPublicMetadataPath(paths, "default", address)); !os.IsNotExist(err) {
		t.Fatalf("component public metadata for ed25519 stat error = %v, want not exist", err)
	}
}

func TestSaveKeyFileWritesComponentPublicMetadata(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	publicKey := bytes.Repeat([]byte{0x29}, 32)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.AttestorComponentEd25519V1, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}

	result, err := SaveKeyFile(paths, &KeyPair{
		Category:      CategoryComponent,
		KeyType:       keytypes.AttestorComponentEd25519V1,
		PublicKeyHex:  hex.EncodeToString(publicKey),
		PrivateKeyHex: strings.Repeat("11", 64),
	}, "default", componentKey, masterKey)
	if err != nil {
		t.Fatalf("SaveKeyFile() error = %v", err)
	}
	if result.Address != componentKey {
		t.Fatalf("Address = %q, want %q", result.Address, componentKey)
	}

	path := ComponentPublicMetadataPath(paths, "default", componentKey)
	assertKeyFileMode(t, path, fsutil.StoreFilePerm)

	env, ok, err := ReadComponentPublicMetadata(paths, "default", componentKey)
	if err != nil {
		t.Fatalf("ReadComponentPublicMetadata() error = %v", err)
	}
	if !ok {
		t.Fatal("ReadComponentPublicMetadata() ok = false, want true")
	}
	if env.ComponentKey != componentKey {
		t.Fatalf("ComponentKey = %q, want %q", env.ComponentKey, componentKey)
	}
	if env.KeyType != keytypes.AttestorComponentEd25519V1 {
		t.Fatalf("KeyType = %q, want %q", env.KeyType, keytypes.AttestorComponentEd25519V1)
	}
	if env.PublicKeyHex != hex.EncodeToString(publicKey) {
		t.Fatalf("PublicKeyHex = %q, want public key", env.PublicKeyHex)
	}
}

func TestSaveKeyFileAllowsCanonicalWriteWithNonCanonicalKeyPresent(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	keyJSON, address := testEd25519Key(t)
	var keyPair KeyPair
	if err := json.Unmarshal(keyJSON, &keyPair); err != nil {
		t.Fatalf("json.Unmarshal(KeyPair) error = %v", err)
	}

	encrypted, err := crypto.EncryptWithMasterKey(keyJSON, masterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey() error = %v", err)
	}
	if err := fsutil.MkdirAll(paths.KeysDir("default")); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}
	existingPath := filepath.Join(paths.KeysDir("default"), "duplicate.key")
	if err := os.WriteFile(existingPath, encrypted, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(existing duplicate) error = %v", err)
	}

	result, err := SaveKeyFile(paths, &keyPair, "default", address, masterKey)
	if err != nil {
		t.Fatalf("SaveKeyFile() error = %v", err)
	}
	if result == nil {
		t.Fatal("SaveKeyFile() result = nil, want saved key")
		return
	}
	if result.PrivateFile != paths.KeyFilePath("default", address) {
		t.Fatalf("SaveKeyFile() path = %q, want canonical key file", result.PrivateFile)
	}
	if _, statErr := os.Stat(paths.KeyFilePath("default", address)); statErr != nil {
		t.Fatalf("canonical key file stat error = %v", statErr)
	}
	if _, statErr := os.Stat(existingPath); statErr != nil {
		t.Fatalf("noncanonical key file stat error = %v", statErr)
	}
}

func TestSaveKeyFileRejectsEmptyMasterKey(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	address := "PLAINADDR"

	keyPair := &KeyPair{
		Category:      CategoryEd25519,
		KeyType:       "ed25519",
		PublicKeyHex:  "aabb",
		PrivateKeyHex: "ccdd",
	}

	result, err := SaveKeyFile(paths, keyPair, "default", address, nil)
	if result != nil {
		t.Fatalf("SaveKeyFile() result = %#v, want nil", result)
	}
	if err == nil {
		t.Fatal("SaveKeyFile() error = nil, want empty master key rejection")
	}
}

func TestSaveKeyFile_SetsDefaults(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())

	keyPair := &KeyPair{
		Category: CategoryEd25519,
		KeyType:  "ed25519",
		// FormatVersion and CreatedAt deliberately not set
	}

	result, err := SaveKeyFile(paths, keyPair, "default", "DEFAULTSADDR", masterKey)
	if err != nil {
		t.Fatalf("SaveKeyFile() error = %v", err)
	}

	data, err := os.ReadFile(result.PrivateFile)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		t.Fatalf("DecryptWithMasterKey() error = %v", err)
	}
	defer crypto.ZeroBytes(decrypted)

	var roundTripped KeyPair
	if err := json.Unmarshal(decrypted, &roundTripped); err != nil {
		t.Fatal(err)
	}

	if roundTripped.FormatVersion != CurrentKeyFormatVersion {
		t.Errorf("FormatVersion = %d, want %d", roundTripped.FormatVersion, CurrentKeyFormatVersion)
	}
	if roundTripped.CreatedAt == "" {
		t.Error("CreatedAt should be set automatically")
	}
}

func TestSaveKeyFile_DirectoryCreation(t *testing.T) {
	masterKey := testMasterKey(t)
	// Use a fresh temp dir — keys directory does not exist yet
	paths := storepaths.NewPaths(t.TempDir())

	keyPair := &KeyPair{
		Category: CategoryEd25519,
		KeyType:  "ed25519",
	}

	_, err := SaveKeyFile(paths, keyPair, "default", "MKDIRADDR", masterKey)
	if err != nil {
		t.Fatalf("SaveKeyFile() error = %v, keys dir should be created automatically", err)
	}

	// Verify directory was created
	keysDir := paths.KeysDir("default")
	info, err := os.Stat(keysDir)
	if err != nil {
		t.Fatalf("keys directory should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
	if got := info.Mode() & os.ModePerm; got != 0o770 {
		t.Fatalf("keys directory mode = %o, want 0770", got)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("keys directory missing setgid bit: %v", info.Mode())
	}
}

func assertKeyFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	if got := info.Mode() & os.ModePerm; got != want {
		t.Fatalf("mode(%s) = %o, want %o", path, got, want)
	}
}
