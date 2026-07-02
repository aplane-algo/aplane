// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

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
