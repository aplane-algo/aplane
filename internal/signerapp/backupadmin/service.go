// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type Deps interface {
	KeyPaths() storepaths.Paths
	GenesisHashMappings() map[string]string
	RestoreLimiter() RestoreLimiter
	WithIdentityMutation(identityID string, fn func() error) error
	Logf(format string, args ...interface{})
}

type Service struct {
	Deps Deps
}

func (s Service) BackupIdentity(ir *identity.Runtime, req adminproto.BackupIdentityRequest) adminproto.BackupIdentityResult {
	passphraseBytes := req.ExportPassphrase
	defer crypto.ZeroBytes(passphraseBytes)
	if err := requireProductRuntime(ir); err != nil {
		return adminproto.BackupIdentityResult{Code: protocol.ResultCodeBackupFailed, Error: err.Error()}
	}

	timestamp := managedBackupTimestamp(time.Now())
	archivePath := backup.BuildManagedArchivePath(s.Deps.KeyPaths(), ir.ID(), timestamp)

	var result *backup.ArchiveResult
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		return ir.WithKeyring(func(masterKey *crypto.Keyring) error {
			var backupErr error
			result, backupErr = backup.CreateKeysArchive(backup.CreateKeysArchiveRequest{
				Paths:            s.Deps.KeyPaths(),
				IdentityID:       ir.ID(),
				ArchivePath:      archivePath,
				Addresses:        req.Addresses,
				Keyring:          masterKey,
				ExportPassphrase: passphraseBytes,
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
	}
}

func managedBackupTimestamp(t time.Time) string {
	return t.UTC().Format("20060102-150405.000000000")
}

func (s Service) ListBackups(ir *identity.Runtime) adminproto.ListBackupsResult {
	if err := requireProductRuntime(ir); err != nil {
		return adminproto.ListBackupsResult{Code: protocol.ResultCodeListBackupsFailed, Error: err.Error()}
	}
	items, err := backup.ListManagedBackups(s.Deps.KeyPaths(), ir.ID())
	if err != nil {
		return adminproto.ListBackupsResult{
			Code:  protocol.ResultCodeListBackupsFailed,
			Error: err.Error(),
		}
	}
	out := make([]adminproto.BackupInfo, len(items))
	for i, item := range items {
		out[i] = adminproto.BackupInfo{
			Path:      item.Path,
			FileName:  item.FileName,
			CreatedAt: item.CreatedAt.Unix(),
			Size:      item.Size,
			Checksum:  item.Checksum,
		}
	}
	return adminproto.ListBackupsResult{Backups: out}
}

func (s Service) DeleteBackup(ir *identity.Runtime, req adminproto.DeleteBackupRequest) adminproto.DeleteBackupResult {
	if err := requireProductRuntime(ir); err != nil {
		return adminproto.DeleteBackupResult{Code: protocol.ResultCodeDeleteBackupFailed, Error: err.Error()}
	}
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		return backup.DeleteManagedBackup(s.Deps.KeyPaths(), ir.ID(), req.ArchivePath)
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

func (s Service) PreviewRestore(ir *identity.Runtime, req adminproto.PreviewRestoreRequest) adminproto.RestorePreviewResult {
	passphraseBytes := req.ExportPassphrase
	defer crypto.ZeroBytes(passphraseBytes)
	if err := requireProductRuntime(ir); err != nil {
		return adminproto.RestorePreviewResult{Code: protocol.ResultCodeRestorePreviewFailed, Error: err.Error()}
	}

	archivePath, err := backup.ResolveManagedBackupPath(s.Deps.KeyPaths(), ir.ID(), req.ArchivePath)
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

	preview, err := backup.PreviewRestoreWithNodeRole(s.Deps.KeyPaths(), ir.ID(), archivePath, passphraseBytes, ir.NodeRole())
	if err != nil {
		if backup.ArchiveAuthenticated(err) {
			limiter.RecordSuccess(archivePath)
		} else {
			limiter.RecordFailure(archivePath)
		}
		return adminproto.RestorePreviewResult{
			Code:  protocol.ResultCodeRestorePreviewFailed,
			Error: err.Error(),
		}
	}
	// Per-credential validation errors occur after manifest authentication;
	// they are not failed export-passphrase guesses.
	limiter.RecordSuccess(archivePath)
	return adminproto.RestorePreviewResult{
		ArchivePath: preview.ArchivePath,
		Keys:        projectRestoreKeyInfos(preview.Keys),
		Errors:      projectRestoreErrors(preview.Errors),
	}
}

func projectRestoreKeyInfos(items []backup.RestoreKeyInfo) []adminproto.RestoreKeyInfo {
	out := make([]adminproto.RestoreKeyInfo, len(items))
	for i, item := range items {
		out[i] = adminproto.RestoreKeyInfo{
			Address:       item.Address,
			KeyType:       item.KeyType,
			AlreadyExists: item.AlreadyExists,
			Error:         item.Error,
		}
	}
	return out
}

func projectRestoreErrors(items []backup.RestoreError) []adminproto.RestoreError {
	out := make([]adminproto.RestoreError, len(items))
	for i, item := range items {
		out[i] = adminproto.RestoreError{
			Address: item.Address,
			Error:   item.Error,
		}
	}
	return out
}
