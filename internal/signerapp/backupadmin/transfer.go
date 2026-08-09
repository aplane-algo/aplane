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
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

const backupUploadPrefix = ".import-"

func (s Service) BeginBackupImport(ir *identity.Runtime, req adminproto.BeginBackupImportRequest) adminproto.BeginBackupImportResult {
	fileName, err := validBackupFileName(req.FileName)
	if err != nil {
		return beginImportError(err)
	}
	var uploadID string
	err = s.Deps.WithIdentityMutation(ir.ID(), func() error {
		dir := s.Deps.KeyPaths().IdentityBackupsDir(ir.ID())
		if err := fsutil.MkdirAll(dir); err != nil {
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
		return beginImportError(err)
	}
	return adminproto.BeginBackupImportResult{Success: true, UploadID: uploadID}
}

func (s Service) AppendBackupImport(ir *identity.Runtime, req adminproto.AppendBackupImportRequest) adminproto.AppendBackupImportResult {
	if req.Offset < 0 || len(req.Data) == 0 || len(req.Data) > adminproto.BackupTransferChunkBytes {
		return appendImportError(fmt.Errorf("invalid backup import chunk"))
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
		return appendImportError(err)
	}
	return adminproto.AppendBackupImportResult{Success: true, NextOffset: next}
}

func (s Service) CommitBackupImport(ir *identity.Runtime, req adminproto.CommitBackupImportRequest) adminproto.CommitBackupImportResult {
	fileName, err := validBackupFileName(req.FileName)
	if err != nil || req.ExpectedSize < 0 || len(req.ExpectedSHA256) != 64 {
		if err == nil {
			err = fmt.Errorf("invalid backup size or checksum")
		}
		return commitImportError(err)
	}
	var info adminproto.BackupInfo
	err = s.Deps.WithIdentityMutation(ir.ID(), func() error {
		dir := s.Deps.KeyPaths().IdentityBackupsDir(ir.ID())
		uploadPath, err := backupUploadPath(dir, req.UploadID)
		if err != nil {
			return err
		}
		checksum, size, err := backup.FileSHA256(uploadPath)
		if err != nil {
			return err
		}
		if size != req.ExpectedSize || checksum != strings.ToLower(req.ExpectedSHA256) {
			return fmt.Errorf("uploaded backup size or checksum mismatch")
		}
		sourceRoot, cleanup, err := backup.PrepareRestoreSource(uploadPath)
		if err != nil {
			return fmt.Errorf("invalid backup archive: %w", err)
		}
		_ = sourceRoot
		cleanup()
		destination := filepath.Join(dir, fileName)
		if _, err := os.Lstat(destination); err == nil {
			return fmt.Errorf("managed backup already exists: %s", fileName)
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(uploadPath, destination); err != nil {
			return err
		}
		if err := fsutil.SyncDir(dir); err != nil {
			return err
		}
		st, err := os.Stat(destination)
		if err != nil {
			return err
		}
		info = adminproto.BackupInfo{Path: destination, FileName: fileName, CreatedAt: st.ModTime().UTC().Unix(), Size: size, Checksum: checksum, Verified: true}
		return nil
	})
	if err != nil {
		return commitImportError(err)
	}
	return adminproto.CommitBackupImportResult{Success: true, Backup: info}
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
		return adminproto.AbortBackupImportResult{Code: "backup_import_abort_failed", Error: err.Error()}
	}
	return adminproto.AbortBackupImportResult{Success: true}
}

func (s Service) ReadBackupChunk(ir *identity.Runtime, req adminproto.ReadBackupChunkRequest) adminproto.ReadBackupChunkResult {
	if req.Offset < 0 {
		return readChunkError(fmt.Errorf("invalid backup offset"))
	}
	fileName, err := validBackupFileName(req.FileName)
	if err != nil {
		return readChunkError(err)
	}
	var result adminproto.ReadBackupChunkResult
	err = s.Deps.WithIdentityMutation(ir.ID(), func() error {
		path, err := backup.ResolveManagedBackupPath(s.Deps.KeyPaths(), ir.ID(), fileName)
		if err != nil {
			return err
		}
		before, err := backup.StatManagedBackupArchive(path)
		if err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()
		after, err := file.Stat()
		if err != nil || !os.SameFile(before, after) {
			return fmt.Errorf("backup archive changed while opening")
		}
		if req.Offset > after.Size() {
			return fmt.Errorf("backup offset exceeds archive size")
		}
		data := make([]byte, adminproto.BackupTransferChunkBytes)
		n, readErr := file.ReadAt(data, req.Offset)
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		result = adminproto.ReadBackupChunkResult{Success: true, FileName: fileName, Offset: req.Offset, Data: data[:n], EOF: req.Offset+int64(n) == after.Size()}
		return nil
	})
	if err != nil {
		return readChunkError(err)
	}
	return result
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
	if filepath.Base(uploadID) != uploadID || !strings.HasPrefix(uploadID, backupUploadPrefix) || !strings.HasSuffix(uploadID, ".part") {
		return "", fmt.Errorf("invalid backup upload ID")
	}
	return filepath.Join(dir, uploadID), nil
}

func beginImportError(err error) adminproto.BeginBackupImportResult {
	return adminproto.BeginBackupImportResult{Code: "backup_import_begin_failed", Error: err.Error()}
}
func appendImportError(err error) adminproto.AppendBackupImportResult {
	return adminproto.AppendBackupImportResult{Code: "backup_import_append_failed", Error: err.Error()}
}
func commitImportError(err error) adminproto.CommitBackupImportResult {
	return adminproto.CommitBackupImportResult{Code: "backup_import_commit_failed", Error: err.Error()}
}
func readChunkError(err error) adminproto.ReadBackupChunkResult {
	return adminproto.ReadBackupChunkResult{Code: "backup_export_read_failed", Error: err.Error()}
}
