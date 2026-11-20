// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

// A generated Ed25519 witness key is saved as a witness credential, named by
// its Witness Key ID rather than by its public key, which is also an
// address, and it loads back as witness key material.
func TestWitnessEd25519GenerateRandomScansAndLoads(t *testing.T) {
	RegisterWitnessKeygen()
	paths := storepaths.NewPaths(t.TempDir())
	passphrase := []byte("component-generator-test-passphrase")
	kr, active := genstoretest.MintFirstAtomic(t, paths, passphrase)
	defer kr.Zero()
	paths = genstoretest.BindActive(t, paths, active)

	g := &WitnessEd25519Generator{}
	result, err := g.GenerateRandom(context.Background(), paths, kr, witness.Ed25519V1, nil)
	if err != nil {
		t.Fatalf("GenerateRandom() error = %v", err)
	}
	if len(result.PublicKeyHex) != witness.Ed25519PublicKeySize*2 {
		t.Fatalf("PublicKeyHex length = %d, want %d", len(result.PublicKeyHex), witness.Ed25519PublicKeySize*2)
	}
	publicKey, err := hex.DecodeString(result.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	wantID, err := witness.ID(witness.Ed25519V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if result.Address != wantID {
		t.Fatalf("Address = %q, want the Witness Key ID %q", result.Address, wantID)
	}

	scan := keystest.ScanKeys(t, paths, kr)
	info, ok := scan[result.Address]
	if !ok {
		t.Fatalf("scan missing cosigner key %q", result.Address)
	}
	if info.Category != keys.CategoryWitness || info.KeyType != witness.Ed25519V1 || info.PublicKeyHex != result.PublicKeyHex {
		t.Fatalf("scan = %+v, want a %s witness with public key %s", info, witness.Ed25519V1, result.PublicKeyHex)
	}

	store := keystore.NewAtomicFileKeyStoreForPaths(paths)
	if err := store.Unlock(passphrase); err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}
	if err := store.Scan(); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	km, err := store.Get(context.Background(), result.Address)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	material, ok := km.Value.(*signing.WitnessKeyMaterial)
	if !ok {
		t.Fatalf("key material value = %T, want *signing.WitnessKeyMaterial", km.Value)
	}
	defer func() {
		securecrypto.ZeroBytes(material.PrivateKey)
		km.Value = nil
	}()
	if material.WitnessKeyID != result.Address || !bytes.Equal(material.PublicKey, publicKey) {
		t.Fatalf("loaded %q with public key %x, want %q", material.WitnessKeyID, material.PublicKey, result.Address)
	}
	if err := validateWitnessPair(material.PublicKey, material.PrivateKey); err != nil {
		t.Fatalf("loaded pair does not validate: %v", err)
	}
}

// The same seed gives the same key, and a seed of the wrong size or another
// key type is refused.
func TestWitnessEd25519GenerateFromSeed(t *testing.T) {
	RegisterWitnessKeygen()
	paths := storepaths.NewPaths(t.TempDir())
	kr, active := genstoretest.MintFirstAtomic(t, paths, []byte("component-generator-test-passphrase"))
	defer kr.Zero()
	paths = genstoretest.BindActive(t, paths, active)

	g := &WitnessEd25519Generator{}
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	result, err := g.GenerateFromSeed(context.Background(), paths, seed, kr, witness.Ed25519V1, nil)
	if err != nil {
		t.Fatalf("GenerateFromSeed() error = %v", err)
	}
	want := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if result.PublicKeyHex != hex.EncodeToString(want) {
		t.Fatalf("PublicKeyHex = %s, want %x", result.PublicKeyHex, want)
	}
	if _, err := g.GenerateFromSeed(context.Background(), paths, seed[:31], kr, witness.Ed25519V1, nil); err == nil {
		t.Fatal("GenerateFromSeed() accepted a 31-byte seed")
	}
	if _, err := g.GenerateFromSeed(context.Background(), paths, seed, kr, witness.Falcon1024V1, nil); err == nil {
		t.Fatal("GenerateFromSeed() accepted another key type")
	}
	if _, err := g.GenerateRandom(context.Background(), paths, kr, "ed25519", nil); err == nil {
		t.Fatal("GenerateRandom() accepted another key type")
	}
}

func TestValidateWitnessPairRefusesMismatchedKeys(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if err := validateWitnessPair(publicKey, privateKey); err != nil {
		t.Fatalf("validateWitnessPair() error = %v", err)
	}
	if err := validateWitnessPair(publicKey, other); err == nil {
		t.Fatal("validateWitnessPair() accepted a mismatched private key")
	}
	if err := validateWitnessPair(publicKey, privateKey[:32]); err == nil {
		t.Fatal("validateWitnessPair() accepted a seed-length private key")
	}
}
