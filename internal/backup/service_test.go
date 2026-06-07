// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	ed25519 "github.com/aplane-algo/aplane/internal/signing/ed25519"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestCreateAllKeysArchiveUsesGroupAccessibleManagedBackupPermissions(t *testing.T) {
	ed25519.RegisterSigner()
	oldUmask := syscall.Umask(0o077)
	defer syscall.Umask(oldUmask)

	const identityID = "default"
	paths := storepaths.NewPaths(t.TempDir())
	if err := fsutil.MkdirAll(paths.KeysDir(identityID)); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}

	address, keyJSON := testEd25519BackupKeyJSON(t)
	encryptedKey, err := crypto.EncryptWithMasterKey(keyJSON, testExportMasterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey() error = %v", err)
	}
	if err := os.WriteFile(paths.KeyFilePath(identityID, address), encryptedKey, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}
	if _, _, err := noderole.SaveInitial(paths, noderole.RoleSigner, timeForBackupTest()); err != nil {
		t.Fatalf("SaveInitial(node role) error = %v", err)
	}
	if err := policy.SaveStoredConfigWithMasterKey(paths.Root(), identityID, &policy.StoredConfig{}, testExportMasterKey, timeForBackupTest()); err != nil {
		t.Fatalf("SaveStoredConfigWithMasterKey() error = %v", err)
	}
	if err := policy.SaveStoredAttestationConfigWithMasterKey(paths.Root(), identityID, &policy.StoredConfig{}, testExportMasterKey, timeForBackupTest()); err != nil {
		t.Fatalf("SaveStoredAttestationConfigWithMasterKey() error = %v", err)
	}

	archivePath := BuildManagedArchivePath(paths, identityID, "20260428-010203")
	if _, err := CreateAllKeysArchive(paths, identityID, archivePath, testExportMasterKey, []byte("export-passphrase")); err != nil {
		t.Fatalf("CreateAllKeysArchive() error = %v", err)
	}

	assertStoreDirMode(t, paths.BackupsRootDir())
	assertStoreDirMode(t, paths.IdentityBackupsDir(identityID))
	assertFileMode(t, archivePath, fsutil.StoreFilePerm)

	extractDir := t.TempDir()
	if err := ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatalf("ExtractTarGzArchive() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "apb", address+".apb")); err != nil {
		t.Fatalf("extracted backup payload stat error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "policy", "policy.yaml")); err != nil {
		t.Fatalf("extracted policy.yaml stat error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "policy", "policy.yaml.hmac")); err != nil {
		t.Fatalf("extracted policy.yaml.hmac stat error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "policy", "attestation.yaml")); err != nil {
		t.Fatalf("extracted attestation.yaml stat error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "policy", "attestation.yaml.hmac")); err != nil {
		t.Fatalf("extracted attestation.yaml.hmac stat error = %v", err)
	}
	manifest, ok, err := ReadManifest(extractDir)
	if err != nil {
		t.Fatalf("ReadManifest() error = %v", err)
	}
	if !ok {
		t.Fatal("backup manifest missing")
	}
	if manifest.SourceNodeRole != string(noderole.RoleSigner) {
		t.Fatalf("manifest source node role = %q, want signer", manifest.SourceNodeRole)
	}
}

func timeForBackupTest() time.Time {
	return time.Unix(1700000000, 0)
}

func assertStoreDirMode(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", path)
	}
	if got := info.Mode() & os.ModePerm; got != 0770 {
		t.Fatalf("mode(%s) = %o, want 0770", path, got)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("mode(%s) missing setgid bit: %v", path, info.Mode())
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	if got := info.Mode() & os.ModePerm; got != want {
		t.Fatalf("mode(%s) = %o, want %o", path, got, want)
	}
}
