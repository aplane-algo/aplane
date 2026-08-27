// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestSavePayloadEncrypted(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	payload := NewEd25519Payload(publicKey, privateKey)
	selector, err := payload.Selector()
	if err != nil {
		t.Fatalf("Selector() error = %v", err)
	}

	result, err := SavePayload(paths, payload, cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("SavePayload() error = %v", err)
	}
	if result.Address != selector {
		t.Fatalf("Address = %q, want %q", result.Address, selector)
	}
	if result.PrivateFile != AccountKeyFilePath(paths, selector) {
		t.Fatalf("PrivateFile = %q, want canonical selector path", result.PrivateFile)
	}

	data, err := os.ReadFile(result.PrivateFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !crypto.IsEncrypted(data) {
		t.Fatal("saved key should be encrypted")
	}
	assertKeyFileMode(t, result.PrivateFile, fsutil.StoreFilePerm)

	decrypted, err := cryptotest.Keyring(t, masterKey).Open(data, mustCredentialContext(t, result.PrivateFile))
	if err != nil {
		t.Fatalf("decryptWithTermKey() error = %v", err)
	}
	defer crypto.ZeroBytes(decrypted)
	roundTripped, err := ParsePayload(decrypted)
	if err != nil {
		t.Fatalf("ParsePayload(round trip) error = %v", err)
	}
	defer roundTripped.ZeroSecrets()
	if roundTripped.KeyType != "ed25519" || roundTripped.Category != CategoryEd25519 {
		t.Fatalf("round trip payload = (%q, %q), want ed25519 native", roundTripped.KeyType, roundTripped.Category)
	}
	if _, err := os.Stat(WitnessPublicMetadataPath(paths, selector)); !os.IsNotExist(err) {
		t.Fatalf("component public metadata for ed25519 stat error = %v, want not exist", err)
	}
}

func TestSavePayloadWritesWitnessPublicMetadata(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	publicKey, privateKey := canonicalFalconComponentPair(t, 0x41)
	payload := NewWitnessPayload(witness.Falcon1024V1, publicKey, privateKey)
	componentKey, err := payload.Selector()
	if err != nil {
		t.Fatalf("Selector() error = %v", err)
	}

	result, err := SavePayload(paths, payload, cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("SavePayload() error = %v", err)
	}
	if result.Address != componentKey {
		t.Fatalf("Address = %q, want %q", result.Address, componentKey)
	}
	wantPrivateFile := SentryCredentialFilePath(paths, componentKey)
	if result.PrivateFile != wantPrivateFile {
		t.Fatalf("PrivateFile = %q, want %q", result.PrivateFile, wantPrivateFile)
	}
	privateData, err := os.ReadFile(result.PrivateFile)
	if err != nil {
		t.Fatalf("ReadFile(private credential) error = %v", err)
	}
	if !crypto.IsEncrypted(privateData) {
		t.Fatal("saved sentry credential should be encrypted")
	}
	if _, err := os.Stat(AccountKeyFilePath(paths, componentKey)); !os.IsNotExist(err) {
		t.Fatalf("legacy witness .key stat error = %v, want not exist", err)
	}

	path := WitnessPublicMetadataPath(paths, componentKey)
	assertKeyFileMode(t, path, fsutil.StoreFilePerm)
	env, ok, err := ReadWitnessPublicMetadata(paths, componentKey)
	if err != nil {
		t.Fatalf("ReadWitnessPublicMetadata() error = %v", err)
	}
	if !ok {
		t.Fatal("ReadWitnessPublicMetadata() ok = false, want true")
	}
	if env.WitnessKeyID != componentKey || env.KeyType != witness.Falcon1024V1 {
		t.Fatalf("component metadata = %+v, want selector/key type", env)
	}
	if wantPublicKey := fmt.Sprintf("%x", publicKey); env.PublicKeyHex != wantPublicKey {
		t.Fatalf("PublicKeyHex = %q, want %q", env.PublicKeyHex, wantPublicKey)
	}
}

func TestSavePayloadRejectsEmptyMasterKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	result, err := SavePayload(storepaths.NewPaths(t.TempDir()), NewEd25519Payload(publicKey, privateKey), nil)
	if result != nil {
		t.Fatalf("SavePayload() result = %#v, want nil", result)
	}
	if err == nil {
		t.Fatal("SavePayload() error = nil, want empty master key rejection")
	}
}

func TestSavePayloadDirectoryCreation(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if _, err := SavePayload(paths, NewEd25519Payload(publicKey, privateKey), cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("SavePayload() error = %v, keys dir should be created automatically", err)
	}
	info, err := os.Stat(activeKeysDirForTest(t, paths))
	if err != nil {
		t.Fatalf("keys directory should exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected keys directory")
	}
	if got := info.Mode() & os.ModePerm; got != 0o700 {
		t.Fatalf("keys directory mode = %o, want 0700", got)
	}
	if info.Mode()&os.ModeSetgid != 0 {
		t.Fatalf("keys directory unexpectedly has setgid bit: %v", info.Mode())
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
