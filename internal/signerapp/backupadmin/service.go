// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"fmt"
	"os"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type Deps interface {
	KeyPaths() storepaths.Paths
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

	timestamp := managedBackupTimestamp(time.Now())
	archivePath := backup.BuildManagedArchivePath(s.Deps.KeyPaths(), ir.ID(), timestamp)

	var result *backup.ArchiveResult
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		return ir.WithMasterKey(func(masterKey []byte) error {
			var backupErr error
			result, backupErr = backup.CreateKeysArchive(s.Deps.KeyPaths(), ir.ID(), archivePath, req.Addresses, masterKey, passphraseBytes)
			return backupErr
		})
	})
	if err != nil {
		return adminproto.BackupIdentityResult{
			Success: false,
			Code:    "backup_failed",
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
	items, err := backup.ListManagedBackups(s.Deps.KeyPaths(), ir.ID())
	if err != nil {
		return adminproto.ListBackupsResult{
			Code:  "list_backups_failed",
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
			Verified:  item.Verified,
		}
	}
	return adminproto.ListBackupsResult{Backups: out}
}

func (s Service) DeleteBackup(ir *identity.Runtime, req adminproto.DeleteBackupRequest) adminproto.DeleteBackupResult {
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		return backup.DeleteManagedBackup(s.Deps.KeyPaths(), ir.ID(), req.ArchivePath)
	})
	if err != nil {
		return adminproto.DeleteBackupResult{
			Success: false,
			Code:    "delete_backup_failed",
			Error:   err.Error(),
		}
	}
	s.Deps.Logf("deleted managed backup via IPC: %s", req.ArchivePath)
	return adminproto.DeleteBackupResult{Success: true}
}

func (s Service) PreviewRestore(ir *identity.Runtime, req adminproto.PreviewRestoreRequest) adminproto.RestorePreviewResult {
	passphraseBytes := req.ExportPassphrase
	defer crypto.ZeroBytes(passphraseBytes)

	archivePath, err := backup.ResolveManagedBackupPath(s.Deps.KeyPaths(), ir.ID(), req.ArchivePath)
	if err != nil {
		return adminproto.RestorePreviewResult{
			Code:  "restore_preview_failed",
			Error: err.Error(),
		}
	}
	limiter := s.Deps.RestoreLimiter()
	if retryAfter := limiter.RetryAfter(ir.ID(), archivePath); retryAfter > 0 {
		return adminproto.RestorePreviewResult{
			ArchivePath: archivePath,
			Code:        "restore_rate_limited",
			Error:       RestoreRateLimitedError(retryAfter),
		}
	}

	preview, err := backup.PreviewRestore(s.Deps.KeyPaths(), ir.ID(), archivePath, passphraseBytes)
	if err != nil {
		limiter.RecordFailure(ir.ID(), archivePath)
		return adminproto.RestorePreviewResult{
			Code:  "restore_preview_failed",
			Error: err.Error(),
		}
	}
	if len(preview.Errors) > 0 {
		limiter.RecordFailure(ir.ID(), archivePath)
	} else {
		limiter.RecordSuccess(ir.ID(), archivePath)
	}
	return adminproto.RestorePreviewResult{
		ArchivePath: preview.ArchivePath,
		Keys:        projectRestoreKeyInfos(preview.Keys),
		Errors:      projectRestoreErrors(preview.Errors),
	}
}

func (s Service) RestoreBackup(ir *identity.Runtime, req adminproto.RestoreBackupRequest) adminproto.RestoreBackupResult {
	passphraseBytes := req.ExportPassphrase
	defer crypto.ZeroBytes(passphraseBytes)

	archivePath, err := backup.ResolveManagedBackupPath(s.Deps.KeyPaths(), ir.ID(), req.ArchivePath)
	if err != nil {
		return adminproto.RestoreBackupResult{
			Code:  "invalid_backup_archive",
			Error: err.Error(),
		}
	}
	if _, err := backup.StatManagedBackupArchive(archivePath); err != nil {
		if os.IsNotExist(err) {
			return adminproto.RestoreBackupResult{
				ArchivePath: archivePath,
				Code:        "backup_archive_not_found",
				Error:       fmt.Sprintf("backup archive not found: %s", archivePath),
			}
		}
		return adminproto.RestoreBackupResult{
			ArchivePath: archivePath,
			Code:        "backup_archive_unavailable",
			Error:       err.Error(),
		}
	}
	limiter := s.Deps.RestoreLimiter()
	if retryAfter := limiter.RetryAfter(ir.ID(), archivePath); retryAfter > 0 {
		return adminproto.RestoreBackupResult{
			ArchivePath: archivePath,
			Code:        "restore_rate_limited",
			Error:       RestoreRateLimitedError(retryAfter),
		}
	}

	sourceRoot, cleanup, err := backup.PrepareRestoreSource(archivePath)
	if err != nil {
		limiter.RecordFailure(ir.ID(), archivePath)
		return adminproto.RestoreBackupResult{
			ArchivePath: archivePath,
			Code:        "prepare_restore_failed",
			Error:       err.Error(),
		}
	}
	defer cleanup()

	keysDir := backup.ResolveBackupKeysDir(sourceRoot)
	addresses := append([]string(nil), req.Addresses...)
	if len(addresses) == 0 {
		addresses, err = backup.ScanBackupFiles(keysDir)
		if err != nil {
			limiter.RecordFailure(ir.ID(), archivePath)
			return adminproto.RestoreBackupResult{
				ArchivePath: archivePath,
				Code:        "scan_backup_failed",
				Error:       err.Error(),
			}
		}
	}
	if len(addresses) == 0 {
		limiter.RecordFailure(ir.ID(), archivePath)
		return adminproto.RestoreBackupResult{
			ArchivePath: archivePath,
			Code:        "empty_backup",
			Error:       fmt.Sprintf("no .apb files found in backup: %s", archivePath),
		}
	}

	result := adminproto.RestoreBackupResult{ArchivePath: archivePath}
	err = s.Deps.WithIdentityMutation(ir.ID(), func() error {
		if err := ir.WithMasterKey(func(masterKey []byte) error {
			for _, address := range addresses {
				if address == "" {
					continue
				}
				if !req.Overwrite {
					if _, statErr := os.Stat(s.Deps.KeyPaths().KeyFilePath(ir.ID(), address)); statErr == nil {
						result.Skipped = append(result.Skipped, adminproto.RestoreKeyInfo{
							Address:       address,
							AlreadyExists: true,
							Error:         "key already exists",
						})
						continue
					}
				}
				warningAddress := address
				restorer := backup.NewRestorer(s.Deps.KeyPaths(), ir.ID()).
					WithLogger(s.Deps.Logf).
					WithWarningHandler(func(keyType, warning string) {
						result.Warnings = append(result.Warnings, adminproto.RestoreWarning{
							Address: warningAddress,
							KeyType: keyType,
							Warning: warning,
						})
					})
				keyType, restoreErr := restorer.RestoreKey(keysDir, address, masterKey, passphraseBytes)
				if restoreErr != nil {
					result.Errors = append(result.Errors, adminproto.RestoreError{
						Address: address,
						Error:   restoreErr.Error(),
					})
					continue
				}
				result.Restored = append(result.Restored, adminproto.RestoreKeyInfo{
					Address: address,
					KeyType: keyType,
				})
			}
			return nil
		}); err != nil {
			return err
		}
		if len(result.Restored) == 0 {
			return nil
		}
		reloadReport, reloadErr := ir.Reload()
		if reloadErr != nil {
			return reloadErr
		}
		if reloadReport != nil {
			result.KeyCount = reloadReport.KeyCount
		}
		return nil
	})
	if err != nil {
		limiter.RecordFailure(ir.ID(), archivePath)
		result.Code = "restore_failed"
		result.Error = err.Error()
		return result
	}
	if len(result.Errors) > 0 {
		limiter.RecordFailure(ir.ID(), archivePath)
		result.Code = "restore_partial"
		result.Error = fmt.Sprintf("%d key(s) failed to restore", len(result.Errors))
		result.Success = false
		return result
	}
	limiter.RecordSuccess(ir.ID(), archivePath)
	result.Success = true
	return result
}

func projectRestoreKeyInfos(items []backup.RestoreKeyInfo) []adminproto.RestoreKeyInfo {
	out := make([]adminproto.RestoreKeyInfo, len(items))
	for i, item := range items {
		out[i] = adminproto.RestoreKeyInfo{
			Address:       item.Address,
			KeyType:       item.KeyType,
			AlreadyExists: item.AlreadyExists,
			HasTemplate:   item.HasTemplate,
			TemplateType:  item.TemplateType,
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
