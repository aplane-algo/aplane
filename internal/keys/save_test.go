// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestSavePayloadEncrypted(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	payload := NewEd25519Payload(publicKey, privateKey)
	selector, err := payload.Selector()
	if err != nil {
		t.Fatalf("Selector() error = %v", err)
	}

	result, err := SavePayload(paths, "default", payload, masterKey)
	if err != nil {
		t.Fatalf("SavePayload() error = %v", err)
	}
	if result.Address != selector {
		t.Fatalf("Address = %q, want %q", result.Address, selector)
	}
	if result.PrivateFile != paths.KeyFilePath("default", selector) {
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

	decrypted, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		t.Fatalf("DecryptWithMasterKey() error = %v", err)
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
	if _, err := os.Stat(ComponentPublicMetadataPath(paths, "default", selector)); !os.IsNotExist(err) {
		t.Fatalf("component public metadata for ed25519 stat error = %v, want not exist", err)
	}
}

func TestSavePayloadWritesComponentPublicMetadata(t *testing.T) {
	masterKey := testMasterKey(t)
	paths := storepaths.NewPaths(t.TempDir())
	publicKey, privateKey := canonicalFalconComponentPair(t, 0x41)
	payload := NewComponentPayload(keytypes.SentryComponentFalcon1024V1, publicKey, privateKey)
	componentKey, err := payload.Selector()
	if err != nil {
		t.Fatalf("Selector() error = %v", err)
	}

	result, err := SavePayload(paths, "default", payload, masterKey)
	if err != nil {
		t.Fatalf("SavePayload() error = %v", err)
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
	if env.ComponentKey != componentKey || env.KeyType != keytypes.SentryComponentFalcon1024V1 {
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
	result, err := SavePayload(storepaths.NewPaths(t.TempDir()), "default", NewEd25519Payload(publicKey, privateKey), nil)
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
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if _, err := SavePayload(paths, "default", NewEd25519Payload(publicKey, privateKey), masterKey); err != nil {
		t.Fatalf("SavePayload() error = %v, keys dir should be created automatically", err)
	}
	info, err := os.Stat(paths.KeysDir("default"))
	if err != nil {
		t.Fatalf("keys directory should exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected keys directory")
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
