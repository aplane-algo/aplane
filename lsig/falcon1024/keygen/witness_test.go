// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"context"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"testing"

	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestSentryFalcon1024GenerateRandomScansAndLoads(t *testing.T) {
	RegisterWitnessKeygen()
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	passphrase := []byte("component-generator-test-passphrase")
	if _, err := securecrypto.CreateKeyringStore(paths.IdentityDir("default"), passphrase); err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	kr, err := securecrypto.OpenKeyringStore(paths.IdentityDir("default"), passphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer kr.Zero()

	g := &WitnessFalcon1024Generator{}
	result, err := g.GenerateRandom(context.Background(), paths, "default", kr, witness.Falcon1024V1, nil)
	if err != nil {
		t.Fatalf("GenerateRandom() error = %v", err)
	}
	if len(result.PublicKeyHex) != falconfamily.PublicKeySize*2 {
		t.Fatalf("PublicKeyHex length = %d, want %d", len(result.PublicKeyHex), falconfamily.PublicKeySize*2)
	}
	if !witness.IsID(result.Address) {
		t.Fatalf("Address = %q, want Witness Key ID", result.Address)
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

	scan, err := keys.ScanKeysDirectoryWithKeyring(paths, "default", kr)
	if err != nil {
		t.Fatalf("ScanKeysDirectoryWithKeyring() error = %v", err)
	}
	info, ok := scan[result.Address]
	if !ok {
		t.Fatalf("scan missing sentry key %q", result.Address)
	}
	if info.Category != keys.CategoryWitness {
		t.Fatalf("scan category = %q, want %q", info.Category, keys.CategoryWitness)
	}
	if info.KeyType != witness.Falcon1024V1 {
		t.Fatalf("scan key type = %q, want %q", info.KeyType, witness.Falcon1024V1)
	}
	if info.PublicKeyHex != result.PublicKeyHex {
		t.Fatalf("scan public key = %q, want %q", info.PublicKeyHex, result.PublicKeyHex)
	}

	store := keystore.NewFileKeyStoreForPaths(paths, "default")
	if err := store.Unlock(passphrase); err != nil {
		t.Fatalf("Unlock() error = %v", err)
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

func TestWitnessFalcon1024GeneratorRejectsWrongKeyType(t *testing.T) {
	g := &WitnessFalcon1024Generator{}
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
	material, ok := km.Value.(*signing.WitnessKeyMaterial)
	if !ok {
		t.Fatalf("key material value = %T, want *signing.WitnessKeyMaterial", km.Value)
	}
	if material.WitnessKeyID != wantSelector {
		t.Fatalf("WitnessKeyID = %q, want %q", material.WitnessKeyID, wantSelector)
	}
	securecrypto.ZeroBytes(material.PrivateKey)
	securecrypto.ZeroBytes(material.PublicKey)
	material.PrivateKey = nil
	material.PublicKey = nil
	km.Value = nil
}
