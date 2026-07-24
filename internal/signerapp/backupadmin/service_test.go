// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

var backupAdminTestPassphrase = []byte("backup-admin-test-passphrase")

func TestManagedBackupTimestampIncludesNanoseconds(t *testing.T) {
	first := managedBackupTimestamp(time.Unix(1700000000, 1))
	second := managedBackupTimestamp(time.Unix(1700000000, 2))
	if first == second {
		t.Fatalf("timestamps are equal: %q", first)
	}
	if !strings.HasSuffix(first, ".000000001") {
		t.Fatalf("timestamp = %q, want nanosecond precision", first)
	}
}

func TestBackupIdentityZeroesRequestPassphraseOnFailure(t *testing.T) {
	passphrase := []byte("export-passphrase")
	service := Service{
		Deps: failingBackupDeps{
			paths: storepaths.NewPaths(t.TempDir()),
		},
	}
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})

	result := service.BackupIdentity(ir, adminproto.BackupIdentityRequest{
		ExportPassphrase: passphrase,
	})

	if result.Success {
		t.Fatal("BackupIdentity() success = true, want failure")
	}
	for i, b := range passphrase {
		if b != 0 {
			t.Fatalf("passphrase byte %d = %d, want zero", i, b)
		}
	}
}

func TestPreviewRestoreRecordsLimiterFailureForMalformedArchive(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath := writeMalformedManagedArchive(t, paths, auth.DefaultIdentityID, "preview")
	limiter := NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) })
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: limiter,
		},
	}
	ir := testBackupIdentityRuntime()

	result := service.PreviewRestore(ir, adminproto.PreviewRestoreRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})

	if result.Code != protocol.ResultCodeRestorePreviewFailed {
		t.Fatalf("PreviewRestore().Code = %q, want %s", result.Code, protocol.ResultCodeRestorePreviewFailed)
	}
	if retryAfter := limiter.RetryAfter(auth.DefaultIdentityID, archivePath); retryAfter == 0 {
		t.Fatal("RetryAfter() = 0, want malformed preview to record limiter failure")
	}

	limited := service.PreviewRestore(ir, adminproto.PreviewRestoreRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if limited.Code != protocol.ResultCodeRestoreRateLimited {
		t.Fatalf("second PreviewRestore().Code = %q, want %s", limited.Code, protocol.ResultCodeRestoreRateLimited)
	}
}

func TestRestoreBackupRecordsLimiterFailureForMalformedArchive(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath := writeMalformedManagedArchive(t, paths, auth.DefaultIdentityID, "restore")
	limiter := NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) })
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: limiter,
		},
	}
	ir := testBackupIdentityRuntime()

	result := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})

	if result.Code != protocol.ResultCodePrepareRestoreFailed {
		t.Fatalf("RestoreBackup().Code = %q, want %s", result.Code, protocol.ResultCodePrepareRestoreFailed)
	}
	if retryAfter := limiter.RetryAfter(auth.DefaultIdentityID, archivePath); retryAfter == 0 {
		t.Fatal("RetryAfter() = 0, want malformed restore to record limiter failure")
	}

	limited := service.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if limited.Code != protocol.ResultCodeRestoreRateLimited {
		t.Fatalf("second RestoreBackup().Code = %q, want %s", limited.Code, protocol.ResultCodeRestoreRateLimited)
	}
}

func TestRecoverBackupAndListRecoveredDoNotReloadOrActivate(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, address := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	limiter := NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) })
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: limiter,
		},
	}
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	exportPassphrase := []byte("export-passphrase")

	result := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: exportPassphrase,
	})
	if !result.Success || result.RestoreID == "" || result.EntryCount != 1 {
		t.Fatalf("RecoverBackup() = %+v, want one inactive batch", result)
	}
	for i, b := range exportPassphrase {
		if b != 0 {
			t.Fatalf("export passphrase byte %d = %d, want zero", i, b)
		}
	}
	if got := reloads.Load(); got != 0 {
		t.Fatalf("runtime reload count = %d, want 0", got)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(paths, auth.DefaultIdentityID, address)); !os.IsNotExist(err) {
		t.Fatalf("active key stat error = %v, want not found", err)
	}

	listed := service.ListRecovered(ir)
	if listed.Error != "" || len(listed.Batches) != 1 {
		t.Fatalf("ListRecovered() = %+v, want one batch", listed)
	}
	if listed.Batches[0].RestoreID != result.RestoreID ||
		listed.Batches[0].ArchiveChecksum != result.ArchiveChecksum ||
		listed.Batches[0].EntryCount != 1 {
		t.Fatalf("ListRecovered() batch = %+v, want result %+v", listed.Batches[0], result)
	}
	if got := reloads.Load(); got != 0 {
		t.Fatalf("runtime reload count after list = %d, want 0", got)
	}
}

func TestRecoverAndListRecoveredFailWithoutMasterKey(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	archivePath, _ := writeRecoverableManagedArchive(t, paths, auth.DefaultIdentityID)
	service := Service{
		Deps: backupServiceTestDeps{
			paths:   paths,
			limiter: NewRestoreAttemptLimiter(func() time.Time { return time.Unix(100, 0) }),
		},
	}
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		KeyStore:      keystore.NewFileKeyStoreForPaths(paths, auth.DefaultIdentityID),
		KeyPaths:      paths,
		Authenticator: auth.NewTokenAuthenticator("token"),
		NodeRole:      noderole.RoleSigner,
	})

	recoverResult := service.RecoverBackup(ir, adminproto.RecoverBackupRequest{
		ArchivePath:      archivePath,
		ExportPassphrase: []byte("export-passphrase"),
	})
	if recoverResult.Code != protocol.ResultCodeRecoverBackupFailed ||
		!strings.Contains(recoverResult.Error, "keystore not unlocked") {
		t.Fatalf("RecoverBackup(locked) = %+v, want locked failure", recoverResult)
	}
	listResult := service.ListRecovered(ir)
	if listResult.Code != protocol.ResultCodeListRecoveredFailed ||
		!strings.Contains(listResult.Error, "keystore not unlocked") {
		t.Fatalf("ListRecovered(locked) = %+v, want locked failure", listResult)
	}
	if _, err := os.Stat(paths.RecoveredRootDir(auth.DefaultIdentityID)); !os.IsNotExist(err) {
		t.Fatalf("recovered root stat error = %v, want not found", err)
	}
}

func writeMalformedManagedArchive(t *testing.T, paths storepaths.Paths, identityID, label string) string {
	t.Helper()

	archivePath := backup.BuildManagedArchivePath(paths, identityID, label)
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o770); err != nil {
		t.Fatalf("MkdirAll(archive dir) error = %v", err)
	}
	if err := os.WriteFile(archivePath, []byte("not a gzip archive"), 0o600); err != nil {
		t.Fatalf("WriteFile(archive) error = %v", err)
	}
	return archivePath
}

func writeRecoverableManagedArchive(t *testing.T, paths storepaths.Paths, identityID string) (string, string) {
	t.Helper()

	root := t.TempDir()
	keysDir := filepath.Join(root, "apb")
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(apb) error = %v", err)
	}
	address, keyJSON := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(keyJSON)
	encrypted, err := crypto.EncryptStandalone(keyJSON, []byte("export-passphrase"))
	if err != nil {
		t.Fatalf("EncryptStandalone() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, address+".apb"), encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile(apb) error = %v", err)
	}
	if err := backup.WriteManifest(root, noderole.RoleSigner, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatalf("WriteManifest() error = %v", err)
	}
	archivePath := backup.BuildManagedArchivePath(paths, identityID, "recover-service")
	if err := backup.CreateTarGzArchive(root, archivePath); err != nil {
		t.Fatalf("CreateTarGzArchive() error = %v", err)
	}
	return archivePath, address
}

func testUnlockedBackupIdentityRuntime(t *testing.T, paths storepaths.Paths, reloads *atomic.Int64) *identity.Runtime {
	t.Helper()

	if _, _, err := crypto.CreateKeystoreMetadata(paths.IdentityDir(auth.DefaultIdentityID), backupAdminTestPassphrase); err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	keyStore := keystore.NewFileKeyStoreForPaths(paths, auth.DefaultIdentityID)
	if _, err := keyStore.InitializeMasterKey(backupAdminTestPassphrase); err != nil {
		t.Fatalf("InitializeMasterKey() error = %v", err)
	}
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		KeyStore:      keyStore,
		KeyPaths:      paths,
		Authenticator: auth.NewTokenAuthenticator("token"),
		NodeRole:      noderole.RoleSigner,
	})
	ir.SetReloadFunc(func(string, []byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		reloads.Add(1)
		return &signertemplates.ReloadReport{}, nil
	})
	ir.SetUnlocked()
	return ir
}

func testBackupIdentityRuntime() *identity.Runtime {
	return identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
}

type backupServiceTestDeps struct {
	paths   storepaths.Paths
	limiter RestoreLimiter
}

func (d backupServiceTestDeps) KeyPaths() storepaths.Paths { return d.paths }
func (d backupServiceTestDeps) RestoreLimiter() RestoreLimiter {
	return d.limiter
}
func (d backupServiceTestDeps) WithIdentityMutation(identityID string, fn func() error) error {
	_ = identityID
	return fn()
}
func (d backupServiceTestDeps) Logf(format string, args ...interface{}) {
	_ = format
	_ = args
}

type failingBackupDeps struct {
	paths storepaths.Paths
}

func (d failingBackupDeps) KeyPaths() storepaths.Paths { return d.paths }
func (d failingBackupDeps) RestoreLimiter() RestoreLimiter {
	return nil
}
func (d failingBackupDeps) WithIdentityMutation(identityID string, fn func() error) error {
	_ = identityID
	_ = fn
	return errors.New("mutation failed")
}
func (d failingBackupDeps) Logf(format string, args ...interface{}) {
	_ = format
	_ = args
}
