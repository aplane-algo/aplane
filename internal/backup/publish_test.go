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
	"github.com/aplane-algo/aplane/internal/keys/keystest"
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
	if err := os.WriteFile(keystest.AccountKeyFilePath(genstoretest.Active(t, paths), address), encryptedKey, fsutil.StoreFilePerm); err != nil {
		t.Fatal(err)
	}
	if _, err := noderole.SaveInitial(paths, noderole.RoleSigner, timeForBackupTest()); err != nil {
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
	if listed[0].Checksum != result.ArchiveChecksum || listed[0].Size != result.ArchiveSize || result.Warning != "" {
		t.Fatalf("result %+v does not describe the published archive %+v", result, listed[0])
	}
}

// A backup that fails after its archive is written and verified, before it
// is given its managed name, leaves nothing behind: no backup is listed, and
// neither the partial archive nor the verification directory remains.
func TestFailedBackupLeavesNothingListed(t *testing.T) {
	paths := storeWithOneKeyForBackupTest(t)
	archivePath := BuildManagedArchivePath(paths, "20260428-010203")
	var sawPartial bool
	beforeArchivePublish = func(partial string) error {
		_, err := os.Lstat(partial)
		sawPartial = err == nil
		return errors.New("simulated failure before publication")
	}
	t.Cleanup(func() { beforeArchivePublish = nil })

	if _, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archivePath, nil, noderole.RoleSigner, cryptotest.Keyring(t, testExportMasterKey))); err == nil {
		t.Fatal("CreateKeysArchive() succeeded though publication failed")
	}
	if !sawPartial {
		t.Fatal("the archive was not written under its partial name before publication")
	}
	if names := backupDirNames(t, paths); len(names) != 0 {
		t.Fatalf("a failed backup left %v in the backup directory", names)
	}
	if listed, err := ListManagedBackups(paths); err != nil || len(listed) != 0 {
		t.Fatalf("ListManagedBackups() after a failed backup = %+v, %v", listed, err)
	}
}

// A directory sync that fails once the archive has its name leaves the
// complete, verified archive published, and says so, as an import does.
func TestBackupWhoseDirectoryCannotBeSyncedIsPublishedWithAWarning(t *testing.T) {
	paths := storeWithOneKeyForBackupTest(t)
	archivePath := BuildManagedArchivePath(paths, "20260428-010203")
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == paths.ProductBackupsDir() {
			if _, err := os.Lstat(archivePath); err == nil {
				return errors.New("simulated backup directory sync failure")
			}
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })

	result, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archivePath, nil, noderole.RoleSigner, cryptotest.Keyring(t, testExportMasterKey)))
	fsutil.TestHook = nil
	if err != nil {
		t.Fatalf("CreateKeysArchive() error = %v", err)
	}
	if !strings.Contains(result.Warning, "durability could not be confirmed") {
		t.Fatalf("warning = %q, want the durability warning", result.Warning)
	}
	listed, err := ListManagedBackups(paths)
	if err != nil || len(listed) != 1 || listed[0].Checksum != result.ArchiveChecksum || listed[0].Size != result.ArchiveSize {
		t.Fatalf("ListManagedBackups() = %+v, %v; want the archive the result describes", listed, err)
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
