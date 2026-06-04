// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"context"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/storepaths"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestAttestorEd25519GenerateRandomScansAndLoads(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	passphrase := []byte("component-generator-test-passphrase")
	if _, _, err := securecrypto.CreateKeystoreMetadata(paths.IdentityDir("default"), passphrase); err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	meta, err := securecrypto.LoadKeystoreMetadata(paths.IdentityDir("default"))
	if err != nil {
		t.Fatalf("LoadKeystoreMetadata() error = %v", err)
	}
	masterKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		t.Fatalf("VerifyAndDeriveMasterKey() error = %v", err)
	}
	defer securecrypto.ZeroBytes(masterKey)

	g := &AttestorEd25519Generator{}
	result, err := g.GenerateRandom(context.Background(), paths, "default", masterKey, keytypes.AttestorComponentEd25519V1, nil)
	if err != nil {
		t.Fatalf("GenerateRandom() error = %v", err)
	}
	if result.PublicKeyHex == "" {
		t.Fatal("PublicKeyHex is empty")
	}
	if !strings.HasPrefix(result.Address, keytypes.ComponentKeySelectorPrefix) {
		t.Fatalf("Address = %q, want %s selector", result.Address, keytypes.ComponentKeySelectorPrefix)
	}
	if result.Address == result.PublicKeyHex {
		t.Fatal("Address unexpectedly equals public key hex")
	}
	if result.Mnemonic != "" {
		t.Fatalf("Mnemonic = %q, want empty", result.Mnemonic)
	}
	if result.KeyFiles == nil || result.KeyFiles.PrivateFile == "" {
		t.Fatalf("KeyFiles = %#v, want private file", result.KeyFiles)
	}

	scan, err := keys.ScanKeysDirectoryWithMasterKey(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithMasterKey() error = %v", err)
	}
	info, ok := scan[result.Address]
	if !ok {
		t.Fatalf("scan missing component key %q", result.Address)
	}
	if info.Category != keys.CategoryComponent {
		t.Fatalf("scan category = %q, want %q", info.Category, keys.CategoryComponent)
	}
	if info.KeyType != keytypes.AttestorComponentEd25519V1 {
		t.Fatalf("scan key type = %q, want %q", info.KeyType, keytypes.AttestorComponentEd25519V1)
	}
	if info.PublicKeyHex != result.PublicKeyHex {
		t.Fatalf("scan public key = %q, want %q", info.PublicKeyHex, result.PublicKeyHex)
	}

	store := keystore.NewFileKeyStoreForPaths(paths, "default")
	if _, err := store.InitializeMasterKey(passphrase); err != nil {
		t.Fatalf("InitializeMasterKey() error = %v", err)
	}
	if err := store.Scan(nil); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	km, err := store.Get(context.Background(), result.Address)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	assertComponentMaterial(t, km, result.Address)
}

func TestAttestorFalcon1024GenerateRandomScansAndLoads(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	passphrase := []byte("component-generator-test-passphrase")
	if _, _, err := securecrypto.CreateKeystoreMetadata(paths.IdentityDir("default"), passphrase); err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	meta, err := securecrypto.LoadKeystoreMetadata(paths.IdentityDir("default"))
	if err != nil {
		t.Fatalf("LoadKeystoreMetadata() error = %v", err)
	}
	masterKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		t.Fatalf("VerifyAndDeriveMasterKey() error = %v", err)
	}
	defer securecrypto.ZeroBytes(masterKey)

	g := &AttestorFalcon1024Generator{}
	result, err := g.GenerateRandom(context.Background(), paths, "default", masterKey, keytypes.AttestorComponentFalcon1024V1, nil)
	if err != nil {
		t.Fatalf("GenerateRandom() error = %v", err)
	}
	if len(result.PublicKeyHex) != falconfamily.PublicKeySize*2 {
		t.Fatalf("PublicKeyHex length = %d, want %d", len(result.PublicKeyHex), falconfamily.PublicKeySize*2)
	}
	if !strings.HasPrefix(result.Address, keytypes.ComponentKeySelectorPrefix) {
		t.Fatalf("Address = %q, want %s selector", result.Address, keytypes.ComponentKeySelectorPrefix)
	}
	if result.Address == result.PublicKeyHex {
		t.Fatalf("Address unexpectedly equals full Falcon public key hex")
	}
	if result.Mnemonic != "" {
		t.Fatalf("Mnemonic = %q, want empty", result.Mnemonic)
	}
	if result.KeyFiles == nil || result.KeyFiles.PrivateFile == "" {
		t.Fatalf("KeyFiles = %#v, want private file", result.KeyFiles)
	}

	scan, err := keys.ScanKeysDirectoryWithMasterKey(paths, "default", masterKey)
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithMasterKey() error = %v", err)
	}
	info, ok := scan[result.Address]
	if !ok {
		t.Fatalf("scan missing component key %q", result.Address)
	}
	if info.Category != keys.CategoryComponent {
		t.Fatalf("scan category = %q, want %q", info.Category, keys.CategoryComponent)
	}
	if info.KeyType != keytypes.AttestorComponentFalcon1024V1 {
		t.Fatalf("scan key type = %q, want %q", info.KeyType, keytypes.AttestorComponentFalcon1024V1)
	}
	if info.PublicKeyHex != result.PublicKeyHex {
		t.Fatalf("scan public key = %q, want %q", info.PublicKeyHex, result.PublicKeyHex)
	}

	store := keystore.NewFileKeyStoreForPaths(paths, "default")
	if _, err := store.InitializeMasterKey(passphrase); err != nil {
		t.Fatalf("InitializeMasterKey() error = %v", err)
	}
	if err := store.Scan(nil); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	km, err := store.Get(context.Background(), result.Address)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	assertComponentMaterial(t, km, result.Address)
}

func TestAttestorEd25519GeneratorRejectsWrongKeyType(t *testing.T) {
	g := &AttestorEd25519Generator{}
	_, err := g.GenerateRandom(context.Background(), storepaths.NewPaths(t.TempDir()), "default", nil, "ed25519", nil)
	if err == nil {
		t.Fatal("GenerateRandom() error = nil, want wrong key type rejection")
	}
}

func TestAttestorFalcon1024GeneratorRejectsWrongKeyType(t *testing.T) {
	g := &AttestorFalcon1024Generator{}
	_, err := g.GenerateRandom(context.Background(), storepaths.NewPaths(t.TempDir()), "default", nil, "ed25519", nil)
	if err == nil {
		t.Fatal("GenerateRandom() error = nil, want wrong key type rejection")
	}
}

func assertComponentMaterial(t *testing.T, km *signing.KeyMaterial, wantSelector string) {
	t.Helper()
	if km == nil {
		t.Fatal("key material is nil")
		return
	}
	material, ok := km.Value.(*signing.ComponentKeyMaterial)
	if !ok {
		t.Fatalf("key material value = %T, want *signing.ComponentKeyMaterial", km.Value)
	}
	if material.ComponentKey != wantSelector {
		t.Fatalf("ComponentKey = %q, want %q", material.ComponentKey, wantSelector)
	}
	securecrypto.ZeroBytes(material.PrivateKey)
	securecrypto.ZeroBytes(material.PublicKey)
	material.PrivateKey = nil
	material.PublicKey = nil
	km.Value = nil
}
