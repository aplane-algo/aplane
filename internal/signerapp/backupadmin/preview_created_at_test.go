// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestPreviewRestoreReportsSealedCreationTime(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	var reloads atomic.Int64
	ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
	installBackupAdminPolicy(t, ir, paths)
	address, payload := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(payload)
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		active, err := genstore.ResolveStoreRootWithKeyring(paths, kr)
		if err != nil {
			return err
		}
		sealed, err := kr.Seal(payload, crypto.AccountKeyContext(address))
		if err != nil {
			return err
		}
		return os.WriteFile(keys.AccountKeyFilePathActive(active, address), sealed, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	service := Service{Deps: backupServiceTestDeps{paths: paths, limiter: NewRestoreAttemptLimiter(time.Now)}, Runtime: ir}
	before := time.Now().Add(-time.Second).Unix()
	created := service.BackupIdentity(adminproto.BackupIdentityRequest{ExportPassphrase: []byte("export-passphrase")})
	if !created.Success {
		t.Fatalf("BackupIdentity() = %+v", created)
	}
	after := time.Now().Add(time.Second).Unix()

	preview := service.PreviewRestore(adminproto.PreviewRestoreRequest{
		ArchivePath: filepath.Base(created.ArchivePath), ExportPassphrase: []byte("export-passphrase"),
	})
	if preview.Error != "" {
		t.Fatalf("PreviewRestore() = %+v", preview)
	}
	if preview.ArchiveCreatedAt < before || preview.ArchiveCreatedAt > after {
		t.Fatalf("ArchiveCreatedAt = %d, want the backup's creation time in [%d, %d]", preview.ArchiveCreatedAt, before, after)
	}
}
