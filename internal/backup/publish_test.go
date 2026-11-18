// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// storeWithOneKeyForBackupTest is a signer store holding one Ed25519 key.
func storeWithOneKeyForBackupTest(t *testing.T) storepaths.Paths {
	t.Helper()
	ed25519signerreg.RegisterSigner()
	paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	address, keyJSON := testEd25519BackupKeyJSON(t)
	encryptedKey, err := cryptotest.Keyring(t, testExportMasterKey).Seal(keyJSON, crypto.AccountKeyContext(address))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(apkeys.AccountKeyFilePathActive(genstoretest.Active(t, paths), address), encryptedKey, fsutil.StoreFilePerm); err != nil {
		t.Fatal(err)
	}
	if _, _, err := noderole.SaveInitial(paths, noderole.RoleSigner, timeForBackupTest()); err != nil {
		t.Fatal(err)
	}
	if err := policy.WriteEmbeddedDefault(activePathsForBackupTest(t, paths), noderole.RoleSigner, cryptotest.Keyring(t, testExportMasterKey), timeForBackupTest()); err != nil {
		t.Fatal(err)
	}
	return paths
}

func backupDirNames(t *testing.T, paths storepaths.Paths) []string {
	t.Helper()
	entries, err := os.ReadDir(paths.ProductBackupsDir())
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// A backup appears under its managed name only once it is complete: its
// directory is synced after it is named, and no partial file is left.
func TestBackupIsPublishedDurablyAndWhole(t *testing.T) {
	paths := storeWithOneKeyForBackupTest(t)
	archivePath := BuildManagedArchivePath(paths, "20260428-010203")
	var synced []string
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync {
			if _, err := os.Lstat(archivePath); err == nil {
				synced = append(synced, path)
			}
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	result, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archivePath, nil, noderole.RoleSigner, cryptotest.Keyring(t, testExportMasterKey)))
	if err != nil {
		t.Fatalf("CreateKeysArchive() error = %v", err)
	}
	if !result.Verified {
		t.Fatal("the result does not say the archive was verified")
	}
	found := false
	for _, dir := range synced {
		found = found || dir == paths.ProductBackupsDir()
	}
	if !found {
		t.Fatalf("the backup directory was not synced once the archive had its name (synced %v)", synced)
	}
	if names := backupDirNames(t, paths); len(names) != 1 || names[0] != filepath.Base(archivePath) {
		t.Fatalf("backup directory holds %v, want only the archive", names)
	}
	listed, err := ListManagedBackups(paths)
	if err != nil || len(listed) != 1 || listed[0].Path != archivePath {
		t.Fatalf("ListManagedBackups() = %+v, %v", listed, err)
	}
}

// A backup that fails after its archive is written leaves no archive behind:
// the listing shows no backup, and no partial file remains.
func TestFailedBackupLeavesNothingListed(t *testing.T) {
	paths := storeWithOneKeyForBackupTest(t)
	archivePath := BuildManagedArchivePath(paths, "20260428-010203")
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == paths.ProductBackupsDir() {
			return errors.New("simulated backup directory sync failure")
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	if _, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archivePath, nil, noderole.RoleSigner, cryptotest.Keyring(t, testExportMasterKey))); err == nil {
		t.Fatal("CreateKeysArchive() succeeded though its archive could not be made durable")
	}
	fsutil.TestHook = nil
	if names := backupDirNames(t, paths); len(names) != 0 {
		t.Fatalf("a failed backup left %v in the backup directory", names)
	}
	if listed, err := ListManagedBackups(paths); err != nil || len(listed) != 0 {
		t.Fatalf("ListManagedBackups() after a failed backup = %+v, %v", listed, err)
	}
}

// A backup never replaces an archive already under its name, and leaves no
// partial file when it refuses.
func TestBackupNeverReplacesAnExistingArchive(t *testing.T) {
	paths := storeWithOneKeyForBackupTest(t)
	archivePath := BuildManagedArchivePath(paths, "20260428-010203")
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, []byte("an earlier backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archivePath, nil, noderole.RoleSigner, cryptotest.Keyring(t, testExportMasterKey)))
	if err == nil || !strings.Contains(err.Error(), "archive already exists") {
		t.Fatalf("CreateKeysArchive() error = %v, want archive already exists", err)
	}
	if data, _ := os.ReadFile(archivePath); string(data) != "an earlier backup" {
		t.Fatalf("the existing archive was replaced: %q", data)
	}
	if names := backupDirNames(t, paths); len(names) != 1 {
		t.Fatalf("backup directory holds %v, want only the earlier archive", names)
	}
}
