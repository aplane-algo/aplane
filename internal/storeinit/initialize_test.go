// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeinit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestInitializeCreatesStoreMetadataKeysAndToken(t *testing.T) {
	dataDir := t.TempDir()
	paths := storepaths.NewPaths(dataDir)
	identityID := "default"
	passphrase := []byte("init-passphrase")
	defer crypto.ZeroBytes(passphrase)

	result, err := Initialize(passphrase, Options{
		DataDir:    dataDir,
		Paths:      paths,
		IdentityID: identityID,
	})
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if result.MetadataDir != paths.KeystoreMetadataDir(identityID) {
		t.Fatalf("MetadataDir = %q, want %q", result.MetadataDir, paths.KeystoreMetadataDir(identityID))
	}
	if !crypto.KeystoreMetadataExistsIn(paths.KeystoreMetadataDir(identityID)) {
		t.Fatal("keystore metadata missing after initialize")
	}
	if _, err := os.Stat(paths.KeysDir(identityID)); err != nil {
		t.Fatalf("keys dir stat error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(paths.IdentityDir(identityID), "aplane.token")); err != nil {
		t.Fatalf("token stat error = %v", err)
	}
	meta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(identityID))
	if err != nil {
		t.Fatalf("LoadKeystoreMetadata() error = %v", err)
	}
	masterKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		t.Fatalf("VerifyAndDeriveMasterKey() error = %v", err)
	}
	defer crypto.ZeroBytes(masterKey)
	if _, err := policy.LoadVerifiedStoredConfigWithMasterKey(dataDir, identityID, masterKey); err != nil {
		t.Fatalf("policy integrity baseline did not verify: %v", err)
	}
}

func TestInitializeRejectsExistingMetadata(t *testing.T) {
	dataDir := t.TempDir()
	paths := storepaths.NewPaths(dataDir)
	identityID := "default"
	if _, masterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), []byte("existing-passphrase")); err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	} else {
		crypto.ZeroBytes(masterKey)
	}

	_, err := Initialize([]byte("new-passphrase"), Options{
		DataDir:    dataDir,
		Paths:      paths,
		IdentityID: identityID,
	})
	if err == nil || !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("Initialize() error = %v, want already-initialized error", err)
	}
}

func TestHasPartialState(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"

	if HasPartialState(paths, identityID) {
		t.Fatal("empty identity dir should not be partial")
	}

	identityDir := paths.IdentityDir(identityID)
	if err := os.MkdirAll(identityDir, 0o770); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(identityDir, "aplane.token"), []byte("token"), 0o600); err != nil {
		t.Fatalf("WriteFile(aplane.token) error = %v", err)
	}
	if HasPartialState(paths, identityID) {
		t.Fatal("token-only identity dir should not be partial")
	}
	if err := os.WriteFile(filepath.Join(identityDir, "orphan.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if !HasPartialState(paths, identityID) {
		t.Fatal("expected orphaned identity dir state to be detected")
	}

	if err := os.WriteFile(filepath.Join(identityDir, ".keystore"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile(.keystore) error = %v", err)
	}
	if HasPartialState(paths, identityID) {
		t.Fatal("presence of .keystore should not be considered partial initialization")
	}
}
