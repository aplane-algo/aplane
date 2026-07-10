// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestCreateAllKeysArchiveUsesGroupAccessibleManagedBackupPermissions(t *testing.T) {
	ed25519signerreg.RegisterSigner()
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

	archivePath := BuildManagedArchivePath(paths, identityID, "20260428-010203")
	if _, err := CreateKeysArchive(paths, identityID, archivePath, nil, testExportMasterKey, []byte("export-passphrase")); err != nil {
		t.Fatalf("CreateKeysArchive() error = %v", err)
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

// TestCreateAllKeysArchiveSkipsInvalidPayloadsAndReports pins the skip-and-report
// contract: an all-keys backup excludes a key whose decrypted payload fails
// canonical validation, reports it in ArchiveResult.Skipped, and still backs up
// the healthy keys. Explicit address selection keeps failing closed.
func TestCreateAllKeysArchiveSkipsInvalidPayloadsAndReports(t *testing.T) {
	ed25519signerreg.RegisterSigner()

	const identityID = "default"
	const badAddress = "BADCANONICALKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
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

	// Decryptable but non-canonical payload (pre-cutover shape with alias field).
	encryptedBad, err := crypto.EncryptWithMasterKey([]byte(`{"key_type":"ed25519","params":{"a":"b"}}`), testExportMasterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey(bad) error = %v", err)
	}
	if err := os.WriteFile(paths.KeyFilePath(identityID, badAddress), encryptedBad, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(bad key) error = %v", err)
	}

	if _, _, err := noderole.SaveInitial(paths, noderole.RoleSigner, timeForBackupTest()); err != nil {
		t.Fatalf("SaveInitial(node role) error = %v", err)
	}
	if err := policy.SaveStoredConfigWithMasterKey(paths.Root(), identityID, &policy.StoredConfig{}, testExportMasterKey, timeForBackupTest()); err != nil {
		t.Fatalf("SaveStoredConfigWithMasterKey() error = %v", err)
	}

	archivePath := BuildManagedArchivePath(paths, identityID, "20260710-010203")
	result, err := CreateKeysArchive(paths, identityID, archivePath, nil, testExportMasterKey, []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("CreateKeysArchive() error = %v", err)
	}
	if result.KeyCount != 1 || len(result.Addresses) != 1 || result.Addresses[0] != address {
		t.Fatalf("exported = %#v (count %d), want only %s", result.Addresses, result.KeyCount, address)
	}
	reason, ok := result.Skipped[badAddress]
	if !ok {
		t.Fatalf("Skipped = %#v, want entry for %s", result.Skipped, badAddress)
	}
	if !strings.Contains(reason, "incompatible key file format") {
		t.Fatalf("skip reason = %q, want canonical-format rejection", reason)
	}

	extractDir := t.TempDir()
	if err := ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatalf("ExtractTarGzArchive() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "apb", address+".apb")); err != nil {
		t.Fatalf("healthy key missing from archive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "apb", badAddress+".apb")); !os.IsNotExist(err) {
		t.Fatalf("invalid key must not be in archive, stat err = %v", err)
	}

	// Explicitly selecting the invalid key still fails closed.
	selectedPath := BuildManagedArchivePath(paths, identityID, "20260710-020304")
	if _, err := CreateKeysArchive(paths, identityID, selectedPath, []string{badAddress}, testExportMasterKey, []byte("export-passphrase")); err == nil {
		t.Fatal("CreateKeysArchive(selected invalid key) should fail closed")
	}
}

// TestCreateAllKeysArchiveFailsWhenNoKeyIsExportable pins that skip-and-report
// never silently produces an empty backup.
func TestCreateAllKeysArchiveFailsWhenNoKeyIsExportable(t *testing.T) {
	const identityID = "default"
	paths := storepaths.NewPaths(t.TempDir())
	if err := fsutil.MkdirAll(paths.KeysDir(identityID)); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}
	encryptedBad, err := crypto.EncryptWithMasterKey([]byte(`{"key_type":"ed25519"}`), testExportMasterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey(bad) error = %v", err)
	}
	badFile := paths.KeyFilePath(identityID, "ONLYINVALIDKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err := os.WriteFile(badFile, encryptedBad, fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(bad key) error = %v", err)
	}

	archivePath := BuildManagedArchivePath(paths, identityID, "20260710-030405")
	_, err = CreateKeysArchive(paths, identityID, archivePath, nil, testExportMasterKey, []byte("export-passphrase"))
	if err == nil || !strings.Contains(err.Error(), "no exportable keys") {
		t.Fatalf("CreateKeysArchive() error = %v, want no-exportable-keys failure", err)
	}
}

// TestExportAllKeysStillAbortsOnDecryptFailure pins the skip boundary: only
// canonical-payload rejections are skipped; infrastructure failures abort.
func TestExportAllKeysStillAbortsOnDecryptFailure(t *testing.T) {
	const identityID = "default"
	paths := storepaths.NewPaths(t.TempDir())
	srcDir := paths.KeysDir(identityID)
	if err := fsutil.MkdirAll(srcDir); err != nil {
		t.Fatalf("MkdirAll(keys) error = %v", err)
	}
	corruptFile := paths.KeyFilePath(identityID, "UNDECRYPTABLEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err := os.WriteFile(corruptFile, []byte("not encrypted data"), fsutil.StoreFilePerm); err != nil {
		t.Fatalf("WriteFile(corrupt) error = %v", err)
	}

	_, _, err := ExportAllKeys(paths, identityID, srcDir, t.TempDir(), testExportMasterKey, []byte("export-passphrase"))
	if err == nil || !strings.Contains(err.Error(), "failed to export") {
		t.Fatalf("ExportAllKeys() error = %v, want decrypt-failure abort", err)
	}
}
