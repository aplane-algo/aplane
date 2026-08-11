// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	backupUploadPrefix     = ".import-"
	backupClaimPrefix      = ".import-claimed-"
	backupValidationPrefix = ".import-validation-"
)

var deepVerifyImportedBackup = backup.DeepVerifyBackupBytes

func (s Service) BeginBackupImport(ir *identity.Runtime, req adminproto.BeginBackupImportRequest) adminproto.BeginBackupImportResult {
	fileName, err := validBackupFileName(req.FileName)
	if err != nil {
		return beginImportError(err, s.Deps.KeyPaths().Root())
	}
	var uploadID string
	err = s.Deps.WithIdentityMutation(ir.ID(), func() error {
		dir := s.Deps.KeyPaths().IdentityBackupsDir(ir.ID())
		if err := fsutil.MkdirAllPrivate(dir); err != nil {
			return err
		}
		// Product mode supports one writable upload per identity. Starting a new
		// transfer supersedes client-disconnect residue, but never a claimed
		// archive undergoing immutable deep validation.
		if _, err := cleanupSupersededBackupUploads(s.Deps.KeyPaths(), ir.ID()); err != nil {
			return err
		}
		if _, err := os.Lstat(filepath.Join(dir, fileName)); err == nil {
			return fmt.Errorf("managed backup already exists: %s", fileName)
		} else if !os.IsNotExist(err) {
			return err
		}
		file, err := os.CreateTemp(dir, backupUploadPrefix+"*.part")
		if err != nil {
			return err
		}
		path := file.Name()
		defer func() { _ = file.Close() }()
		if err := file.Chmod(0o600); err != nil {
			_ = os.Remove(path)
			return err
		}
		if err := file.Sync(); err != nil {
			_ = os.Remove(path)
			return err
		}
		if err := fsutil.SyncDir(dir); err != nil {
			_ = os.Remove(path)
			return err
		}
		uploadID = filepath.Base(path)
		return nil
	})
	if err != nil {
		return beginImportError(err, s.Deps.KeyPaths().Root())
	}
	return adminproto.BeginBackupImportResult{Success: true, UploadID: uploadID}
}

func (s Service) AppendBackupImport(ir *identity.Runtime, req adminproto.AppendBackupImportRequest) adminproto.AppendBackupImportResult {
	if req.Offset < 0 || len(req.Data) == 0 || len(req.Data) > adminproto.BackupTransferChunkBytes {
		return appendImportError(fmt.Errorf("invalid backup import chunk"), s.Deps.KeyPaths().Root())
	}
	var next int64
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		path, err := backupUploadPath(s.Deps.KeyPaths().IdentityBackupsDir(ir.ID()), req.UploadID)
		if err != nil {
			return err
		}
		before, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
			return fmt.Errorf("backup upload is not a regular file")
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()
		after, err := file.Stat()
		if err != nil || !os.SameFile(before, after) {
			return fmt.Errorf("backup upload changed while opening")
		}
		if after.Size() != req.Offset {
			return fmt.Errorf("backup upload offset is %d, expected %d", req.Offset, after.Size())
		}
		if after.Size() > adminproto.MaxBackupImportBytes-int64(len(req.Data)) {
			return fmt.Errorf("backup import exceeds maximum size %d", adminproto.MaxBackupImportBytes)
		}
		written, err := file.Write(req.Data)
		if err != nil {
			return err
		}
		if written != len(req.Data) {
			return io.ErrShortWrite
		}
		if err := file.Sync(); err != nil {
			return err
		}
		next = req.Offset + int64(written)
		return nil
	})
	if err != nil {
		return appendImportError(err, s.Deps.KeyPaths().Root())
	}
	return adminproto.AppendBackupImportResult{Success: true, NextOffset: next}
}

func (s Service) CommitBackupImport(ir *identity.Runtime, req adminproto.CommitBackupImportRequest) adminproto.CommitBackupImportResult {
	defer crypto.ZeroBytes(req.ExportPassphrase)
	fileName, err := validBackupFileName(req.FileName)
	if err != nil || req.ExpectedSize <= 0 || req.ExpectedSize > adminproto.MaxBackupImportBytes || len(req.ExpectedSHA256) != 64 || len(req.ExportPassphrase) == 0 {
		if err == nil {
			err = fmt.Errorf("invalid backup size, checksum, or export passphrase")
		}
		return commitImportError(err, s.Deps.KeyPaths().Root())
	}
	dir := s.Deps.KeyPaths().IdentityBackupsDir(ir.ID())
	claimPath, err := s.claimBackupImport(ir.ID(), dir, req.UploadID, fileName, req.ExpectedSize)
	if err != nil {
		return commitImportError(err, s.Deps.KeyPaths().Root())
	}
	claimPublished := false
	defer func() {
		if !claimPublished {
			_ = fsutil.RemoveDurable(claimPath)
		}
	}()

	checksum, size, err := backup.FileSHA256(claimPath)
	if err != nil {
		return commitImportError(err, s.Deps.KeyPaths().Root())
	}
	if size != req.ExpectedSize || checksum != strings.ToLower(req.ExpectedSHA256) {
		return commitImportError(fmt.Errorf("uploaded backup size or checksum mismatch"), s.Deps.KeyPaths().Root())
	}
	sourceRoot, err := os.MkdirTemp(dir, backupValidationPrefix+"*")
	if err != nil {
		return commitImportError(fmt.Errorf("create backup validation directory: %w", err), s.Deps.KeyPaths().Root())
	}
	defer func() {
		if sourceRoot != "" {
			_ = removeBackupValidationDirectory(sourceRoot)
		}
	}()
	if err := backup.ExtractTarGzArchive(claimPath, sourceRoot); err != nil {
		return commitImportError(fmt.Errorf("invalid backup archive: %w", err), s.Deps.KeyPaths().Root())
	}
	report, err := deepVerifyImportedBackup(sourceRoot, req.ExportPassphrase)
	if err != nil {
		return commitImportError(fmt.Errorf("invalid backup contents: %w", err), s.Deps.KeyPaths().Root())
	}
	if report.FailedFiles > 0 {
		return commitImportError(
			fmt.Errorf("invalid backup contents: %d of %d credential files failed validation", report.FailedFiles, report.TotalFiles),
			s.Deps.KeyPaths().Root(),
		)
	}
	if err := removeBackupValidationDirectory(sourceRoot); err != nil {
		return commitImportError(fmt.Errorf("remove backup validation directory: %w", err), s.Deps.KeyPaths().Root())
	}
	sourceRoot = ""

	var info adminproto.BackupInfo
	err = s.Deps.WithIdentityMutation(ir.ID(), func() error {
		destination := filepath.Join(dir, fileName)
		if _, err := os.Lstat(destination); err == nil {
			return fmt.Errorf("managed backup already exists: %s", fileName)
		} else if !os.IsNotExist(err) {
			return err
		}
		claimInfo, err := os.Lstat(claimPath)
		if err != nil {
			return err
		}
		if claimInfo.Mode()&os.ModeSymlink != 0 || !claimInfo.Mode().IsRegular() || claimInfo.Size() != size {
			return fmt.Errorf("claimed backup upload changed during validation")
		}
		if err := os.Rename(claimPath, destination); err != nil {
			return err
		}
		claimPublished = true
		if err := fsutil.SyncDir(dir); err != nil {
			return err
		}
		st, err := os.Stat(destination)
		if err != nil {
			return err
		}
		info = adminproto.BackupInfo{Path: destination, FileName: fileName, CreatedAt: st.ModTime().UTC().Unix(), Size: size, Checksum: checksum}
		return nil
	})
	if err != nil {
		return commitImportError(err, s.Deps.KeyPaths().Root())
	}
	return adminproto.CommitBackupImportResult{Success: true, Backup: info}
}

func (s Service) claimBackupImport(identityID, dir, uploadID, fileName string, expectedSize int64) (string, error) {
	var claimPath string
	err := s.Deps.WithIdentityMutation(identityID, func() error {
		uploadPath, err := backupUploadPath(dir, uploadID)
		if err != nil {
			return err
		}
		uploadInfo, err := os.Lstat(uploadPath)
		if err != nil {
			return err
		}
		if uploadInfo.Mode()&os.ModeSymlink != 0 || !uploadInfo.Mode().IsRegular() {
			return fmt.Errorf("backup upload is not a regular file")
		}
		if uploadInfo.Size() != expectedSize {
			return fmt.Errorf("uploaded backup size mismatch")
		}
		destination := filepath.Join(dir, fileName)
		if _, err := os.Lstat(destination); err == nil {
			return fmt.Errorf("managed backup already exists: %s", fileName)
		} else if !os.IsNotExist(err) {
			return err
		}
		claimPath, err = backupClaimPath(dir, uploadID)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(claimPath); err == nil {
			return fmt.Errorf("backup upload is already being validated")
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(uploadPath, claimPath); err != nil {
			return err
		}
		return fsutil.SyncDir(dir)
	})
	return claimPath, err
}

func (s Service) AbortBackupImport(ir *identity.Runtime, req adminproto.AbortBackupImportRequest) adminproto.AbortBackupImportResult {
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		path, err := backupUploadPath(s.Deps.KeyPaths().IdentityBackupsDir(ir.ID()), req.UploadID)
		if err != nil {
			return err
		}
		return fsutil.RemoveDurable(path)
	})
	if err != nil {
		return adminproto.AbortBackupImportResult{Code: "backup_import_abort_failed", Error: backupTransferErrorText(err, s.Deps.KeyPaths().Root())}
	}
	return adminproto.AbortBackupImportResult{Success: true}
}

func (s Service) ReadBackupChunk(ir *identity.Runtime, req adminproto.ReadBackupChunkRequest) adminproto.ReadBackupChunkResult {
	if req.Offset < 0 {
		return readChunkError(fmt.Errorf("invalid backup offset"), s.Deps.KeyPaths().Root())
	}
	fileName, err := validBackupFileName(req.FileName)
	if err != nil {
		return readChunkError(err, s.Deps.KeyPaths().Root())
	}
	path, err := backup.ResolveManagedBackupPath(s.Deps.KeyPaths(), ir.ID(), fileName)
	if err != nil {
		return readChunkError(err, s.Deps.KeyPaths().Root())
	}
	before, err := backup.StatManagedBackupArchive(path)
	if err != nil {
		return readChunkError(err, s.Deps.KeyPaths().Root())
	}
	file, err := os.Open(path)
	if err != nil {
		return readChunkError(err, s.Deps.KeyPaths().Root())
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return readChunkError(fmt.Errorf("backup archive changed while opening"), s.Deps.KeyPaths().Root())
	}
	if req.Offset > after.Size() {
		return readChunkError(fmt.Errorf("backup offset exceeds archive size"), s.Deps.KeyPaths().Root())
	}
	data := make([]byte, adminproto.BackupTransferChunkBytes)
	n, readErr := file.ReadAt(data, req.Offset)
	if readErr != nil && readErr != io.EOF {
		return readChunkError(readErr, s.Deps.KeyPaths().Root())
	}
	return adminproto.ReadBackupChunkResult{Success: true, FileName: fileName, Offset: req.Offset, Data: data[:n], EOF: req.Offset+int64(n) == after.Size()}
}

// CleanupIncompleteBackupImports durably removes unpublished upload residue.
// Callers serialize it with other identity mutations once the daemon is live.
func CleanupIncompleteBackupImports(paths storepaths.Paths, identityID string) (int, error) {
	return cleanupBackupImportResidue(paths, identityID, true)
}

func cleanupSupersededBackupUploads(paths storepaths.Paths, identityID string) (int, error) {
	return cleanupBackupImportResidue(paths, identityID, false)
}

func cleanupBackupImportResidue(paths storepaths.Paths, identityID string, includeValidation bool) (int, error) {
	dir := paths.IdentityBackupsDir(identityID)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		name := entry.Name()
		incompleteUpload := strings.HasPrefix(name, backupUploadPrefix) &&
			!strings.HasPrefix(name, backupClaimPrefix) && strings.HasSuffix(name, ".part")
		claimedUpload := includeValidation && strings.HasPrefix(name, backupClaimPrefix) && strings.HasSuffix(name, ".part")
		validationDirectory := strings.HasPrefix(name, backupValidationPrefix)
		if !incompleteUpload && !claimedUpload && (!includeValidation || !validationDirectory) {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return removed, err
		}
		if (incompleteUpload || claimedUpload) && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
			return removed, fmt.Errorf("incomplete backup upload is not a regular file: %s", path)
		}
		if validationDirectory && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
			return removed, fmt.Errorf("backup validation residue is not a real directory: %s", path)
		}
		if incompleteUpload || claimedUpload {
			if err := fsutil.RemoveDurable(path); err != nil {
				return removed, err
			}
		} else if err := removeBackupValidationDirectory(path); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func removeBackupValidationDirectory(path string) error {
	parent := filepath.Dir(path)
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	return fsutil.SyncDir(parent)
}

func validBackupFileName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	name = filepath.Base(trimmed)
	if name != trimmed || name == "." || name == string(filepath.Separator) || !backup.IsArchivePath(name) {
		return "", fmt.Errorf("invalid managed backup filename")
	}
	return name, nil
}

func backupUploadPath(dir, uploadID string) (string, error) {
	if filepath.Base(uploadID) != uploadID || !strings.HasPrefix(uploadID, backupUploadPrefix) ||
		strings.HasPrefix(uploadID, backupClaimPrefix) || !strings.HasSuffix(uploadID, ".part") {
		return "", fmt.Errorf("invalid backup upload ID")
	}
	return filepath.Join(dir, uploadID), nil
}

func backupClaimPath(dir, uploadID string) (string, error) {
	if _, err := backupUploadPath(dir, uploadID); err != nil {
		return "", err
	}
	suffix := strings.TrimPrefix(uploadID, backupUploadPrefix)
	return filepath.Join(dir, backupClaimPrefix+suffix), nil
}

func beginImportError(err error, storeRoot string) adminproto.BeginBackupImportResult {
	return adminproto.BeginBackupImportResult{Code: "backup_import_begin_failed", Error: backupTransferErrorText(err, storeRoot)}
}
func appendImportError(err error, storeRoot string) adminproto.AppendBackupImportResult {
	return adminproto.AppendBackupImportResult{Code: "backup_import_append_failed", Error: backupTransferErrorText(err, storeRoot)}
}
func commitImportError(err error, storeRoot string) adminproto.CommitBackupImportResult {
	return adminproto.CommitBackupImportResult{Code: "backup_import_commit_failed", Error: backupTransferErrorText(err, storeRoot)}
}
func readChunkError(err error, storeRoot string) adminproto.ReadBackupChunkResult {
	return adminproto.ReadBackupChunkResult{Code: "backup_export_read_failed", Error: backupTransferErrorText(err, storeRoot)}
}

func backupTransferErrorText(err error, storeRoot string) string {
	message := err.Error()
	root := filepath.Clean(storeRoot)
	if root != "." && root != string(filepath.Separator) {
		message = strings.ReplaceAll(message, root, "<signer-store>")
	}
	return message
}
