// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type Deps interface {
	DataDir() string
	Config() *serverconfig.ServerConfig
	KeyPaths() storepaths.Paths
	GenesisHashMappings() map[string]string
	RestoreLimiter() RestoreLimiter
	WithStoreMutation(fn func() error) error
	Logf(format string, args ...interface{})
}

type Service struct {
	Deps    Deps
	Runtime *productruntime.Runtime
}

func (s Service) BackupIdentity(req adminproto.BackupIdentityRequest) adminproto.BackupIdentityResult {
	ir := s.Runtime
	passphraseBytes := req.ExportPassphrase
	defer crypto.ZeroBytes(passphraseBytes)

	timestamp := managedBackupTimestamp(time.Now())
	archivePath := backup.BuildManagedArchivePath(s.Deps.KeyPaths(), timestamp)

	var result *backup.ArchiveResult
	err := s.Deps.WithStoreMutation(func() error {
		return ir.WithKeyring(func(masterKey *crypto.Keyring) error {
			active, err := genstore.ResolveStoreRootWithKeyring(s.Deps.KeyPaths(), masterKey)
			if err != nil {
				return err
			}
			bound, err := s.Deps.KeyPaths().BindActive(active)
			if err != nil {
				return err
			}
			var backupErr error
			result, backupErr = backup.CreateKeysArchive(backup.CreateKeysArchiveRequest{
				Paths:              bound,
				RotatingStageHints: backup.SnapshotRotatingHints(ir.StageTables()),
				ArchivePath:        archivePath,
				Addresses:          req.Addresses,
				Keyring:            masterKey,
				ExportPassphrase:   passphraseBytes,
			})
			return backupErr
		})
	})
	if err != nil {
		return adminproto.BackupIdentityResult{
			Success: false,
			Code:    protocol.ResultCodeBackupFailed,
			Error:   err.Error(),
		}
	}

	s.Deps.Logf("created managed backup via IPC: %s", result.ArchivePath)
	return adminproto.BackupIdentityResult{
		Success:         true,
		ArchivePath:     result.ArchivePath,
		ArchiveChecksum: result.ArchiveChecksum,
		ArchiveSize:     result.ArchiveSize,
		KeyCount:        result.KeyCount,
		Addresses:       append([]string(nil), result.Addresses...),
		Verified:        result.Verified,
		Warning:         result.Warning,
	}
}

func managedBackupTimestamp(t time.Time) string {
	return t.UTC().Format(backup.ManagedArchiveTimestampLayout)
}

func (s Service) ListBackups() adminproto.ListBackupsResult {
	items, err := backup.ListManagedBackups(s.Deps.KeyPaths())
	if err != nil {
		return adminproto.ListBackupsResult{
			Code:  protocol.ResultCodeListBackupsFailed,
			Error: err.Error(),
		}
	}
	out := make([]adminproto.BackupInfo, len(items))
	for i, item := range items {
		out[i] = adminproto.BackupInfo{
			FileName:  item.FileName,
			CreatedAt: item.CreatedAt.Unix(),
			Size:      item.Size,
			Checksum:  item.Checksum,
		}
	}
	return adminproto.ListBackupsResult{Backups: out}
}

func (s Service) DeleteBackup(req adminproto.DeleteBackupRequest) adminproto.DeleteBackupResult {
	err := s.Deps.WithStoreMutation(func() error {
		return backup.DeleteManagedBackup(s.Deps.KeyPaths(), req.ArchivePath)
	})
	if err != nil {
		return adminproto.DeleteBackupResult{
			Success: false,
			Code:    protocol.ResultCodeDeleteBackupFailed,
			Error:   err.Error(),
		}
	}
	s.Deps.Logf("deleted managed backup via IPC: %s", req.ArchivePath)
	return adminproto.DeleteBackupResult{Success: true}
}

func (s Service) PreviewRestore(req adminproto.PreviewRestoreRequest) adminproto.RestorePreviewResult {
	ir := s.Runtime
	passphraseBytes := req.ExportPassphrase
	defer crypto.ZeroBytes(passphraseBytes)

	archivePath, err := backup.ResolveManagedBackupPath(s.Deps.KeyPaths(), req.ArchivePath)
	if err != nil {
		return adminproto.RestorePreviewResult{
			Code:  protocol.ResultCodeRestorePreviewFailed,
			Error: err.Error(),
		}
	}
	limiter := s.Deps.RestoreLimiter()
	if retryAfter := limiter.RetryAfter(archivePath); retryAfter > 0 {
		return adminproto.RestorePreviewResult{
			ArchivePath: archivePath,
			Code:        protocol.ResultCodeRestoreRateLimited,
			Error:       RestoreRateLimitedError(retryAfter),
		}
	}

	var preview *backup.RestorePreview
	tried := false
	err = ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		active, resolveErr := genstore.ResolveStoreRootWithKeyring(s.Deps.KeyPaths(), masterKey)
		if resolveErr != nil {
			return resolveErr
		}
		bound, bindErr := s.Deps.KeyPaths().BindActive(active)
		if bindErr != nil {
			return bindErr
		}
		var previewErr error
		tried = true
		preview, previewErr = backup.PreviewRestoreWithNodeRole(bound, archivePath, passphraseBytes, ir.NodeRole())
		return previewErr
	})
	if err != nil {
		// As for a restore, only an attempt that read the archive with the
		// passphrase counts.
		switch {
		case backup.ArchiveAuthenticated(err):
			limiter.RecordSuccess(archivePath)
		case tried:
			limiter.RecordFailure(archivePath)
		}
		return adminproto.RestorePreviewResult{
			Code:  protocol.ResultCodeRestorePreviewFailed,
			Error: err.Error(),
		}
	}
	// Skipped credentials are admitted or not after manifest authentication;
	// they are not failed export-passphrase guesses.
	limiter.RecordSuccess(archivePath)
	skipped, omitted := projectSkippedEntries(preview.Skipped)
	return adminproto.RestorePreviewResult{
		ArchivePath:      preview.ArchivePath,
		ArchiveCreatedAt: preview.CreatedAtUnix,
		Keys:             projectRestoreKeyInfos(preview.Keys),
		Skipped:          skipped,
		SkippedOmitted:   omitted,
	}
}

func projectRestoreKeyInfos(items []backup.RestoreKeyInfo) []adminproto.RestoreKeyInfo {
	out := make([]adminproto.RestoreKeyInfo, len(items))
	for i, item := range items {
		out[i] = adminproto.RestoreKeyInfo{
			Address:       item.Address,
			KeyType:       item.KeyType,
			AlreadyExists: item.AlreadyExists,
			HasPolicy:     item.HasPolicy,
		}
		if item.StageHint != nil {
			n := item.StageHint.Stage
			out[i].StageHint = &n
			out[i].StageHintRound = item.StageHint.ObservedRound
		}
	}
	return out
}

// requireUnlockedOrRecovery refuses a restore or rollback that reached the
// store mutation lock on a signer neither unlocked nor in recovery. The
// handler's gate ran before the request queued on the lock, and a lock and a
// new unlock since can leave the keyring open on a signer not yet published
// unlocked: a commit there whose reload failed would call SetRecovery on a
// locked signer, which does nothing, and the unlock would then publish
// unlocked over a generation the runtime had not followed. The caller holds
// the store mutation lock.
func requireUnlockedOrRecovery(ir *productruntime.Runtime) error {
	switch ir.GetState() {
	case signerruntime.SignerStateUnlocked, signerruntime.SignerStateRecovery:
		return nil
	}
	return fmt.Errorf("signer is locked: %w", keystore.ErrStoreLocked)
}
