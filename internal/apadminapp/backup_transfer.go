// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// The file side of moving a managed backup between the signer's repository
// and this machine. The batch commands and the TUI drive the same helpers:
// the batch commands request chunks synchronously, the TUI from its message
// loop.

// BackupImportSource is a local archive checked for import.
type BackupImportSource struct {
	Path     string
	Name     string
	Checksum string
	Size     int64
}

// PrepareBackupImportSource checks that source is a regular backup archive
// file, not a symlink, and returns its name, SHA-256, and size for the import
// transfer. The daemon validates the contents with the export passphrase.
func PrepareBackupImportSource(source string) (BackupImportSource, error) {
	if !backup.IsArchivePath(source) {
		return BackupImportSource{}, fmt.Errorf("backup source must end in .tar.gz or .tgz: %s", source)
	}
	info, err := os.Lstat(source)
	if err != nil {
		return BackupImportSource{}, fmt.Errorf("backup source unavailable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return BackupImportSource{}, fmt.Errorf("backup source must be a regular file, not a symlink: %s", source)
	}
	if _, err := backup.StatManagedBackupArchive(source); err != nil {
		return BackupImportSource{}, protocol.WithCode("invalid_backup", fmt.Errorf("failed to validate imported backup archive: %w", err))
	}
	checksum, size, err := backup.FileSHA256(source)
	if err != nil {
		return BackupImportSource{}, fmt.Errorf("failed to checksum backup source: %w", err)
	}
	return BackupImportSource{Path: source, Name: filepath.Base(source), Checksum: checksum, Size: size}, nil
}

// CheckBackupExportDestination checks that destinationDir can receive an
// export: a directory, or a path where one can be created. It does not
// create it.
func CheckBackupExportDestination(destinationDir string) error {
	if backup.IsArchivePath(destinationDir) {
		return fmt.Errorf("backup export destination must be a directory, not an archive path: %s", destinationDir)
	}
	info, err := os.Stat(destinationDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to inspect backup export destination directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("backup export destination is not a directory: %s", destinationDir)
	}
	return nil
}

// BackupExportWriter receives one managed archive's chunks into a private
// staging file in the destination directory, verifies the result against
// the listing, and publishes it under the archive's name without replacing
// anything.
type BackupExportWriter struct {
	info           protocol.BackupInfo
	destinationDir string
	destination    string
	tmp            *os.File
	tmpPath        string
	written        int64
	finished       bool
}

// BeginBackupExport prepares to export the listed backup into
// destinationDir, creating the directory (0700) if needed. It refuses when
// the destination file already exists.
func BeginBackupExport(destinationDir string, info protocol.BackupInfo) (*BackupExportWriter, error) {
	if err := CheckBackupExportDestination(destinationDir); err != nil {
		return nil, err
	}
	fileName := filepath.Base(info.FileName)
	if fileName == "." || fileName == string(filepath.Separator) || fileName != info.FileName {
		return nil, fmt.Errorf("managed backup has invalid filename: %s", info.FileName)
	}
	if err := os.MkdirAll(destinationDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create backup export destination directory: %w", err)
	}
	destination := filepath.Join(destinationDir, fileName)
	if _, err := os.Lstat(destination); err == nil {
		return nil, fmt.Errorf("backup export destination already exists: %s", destination)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	tmp, err := os.CreateTemp(destinationDir, ".aplane-backup-export-*.part")
	if err != nil {
		return nil, err
	}
	w := &BackupExportWriter{info: info, destinationDir: destinationDir, destination: destination, tmp: tmp, tmpPath: tmp.Name()}
	if err := tmp.Chmod(0o600); err != nil {
		w.Abort()
		return nil, err
	}
	return w, nil
}

// Destination is the path the export publishes to.
func (w *BackupExportWriter) Destination() string { return w.destination }

// Written is how many bytes have been received, the offset of the next chunk.
func (w *BackupExportWriter) Written() int64 { return w.written }

// Write appends one chunk. It reports done when the chunk is the last one.
func (w *BackupExportWriter) Write(chunk protocol.BackupChunkMessage) (done bool, err error) {
	if !chunk.Success {
		return false, resultError("backup export failed", chunk.Code, chunk.Error)
	}
	if chunk.Offset != w.written {
		return false, fmt.Errorf("backup export returned offset %d, expected %d", chunk.Offset, w.written)
	}
	if len(chunk.Data) > 0 {
		if _, err := w.tmp.Write(chunk.Data); err != nil {
			return false, err
		}
		w.written += int64(len(chunk.Data))
	}
	if chunk.EOF {
		return true, nil
	}
	if len(chunk.Data) == 0 {
		return false, errors.New("backup export returned empty non-final chunk")
	}
	return false, nil
}

// Finish verifies the received bytes against the listed size and SHA-256 and
// publishes them. Warnings report problems after the export was committed.
// The staging file is removed whatever the outcome.
func (w *BackupExportWriter) Finish() (checksum string, warnings []string, err error) {
	defer w.Abort()
	if err := w.tmp.Sync(); err != nil {
		return "", nil, err
	}
	if err := w.tmp.Close(); err != nil {
		return "", nil, err
	}
	checksum, size, err := backup.FileSHA256(w.tmpPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to verify exported backup: %w", err)
	}
	if size != w.info.Size {
		return "", nil, protocol.WithCode("verification_failed", fmt.Errorf("exported backup size mismatch: got %d, want %d", size, w.info.Size))
	}
	if w.info.Checksum != "" && checksum != w.info.Checksum {
		return "", nil, protocol.WithCode("verification_failed", fmt.Errorf("exported backup checksum mismatch: got %s, want %s", checksum, w.info.Checksum))
	}
	publication, err := publishBackupExportNoReplace(w.tmpPath, w.destination)
	if err != nil {
		return "", nil, err
	}
	w.finished = true
	warnings = publication.Warnings
	if err := fsutil.SyncDir(w.destinationDir); err != nil {
		warnings = append(warnings, fmt.Sprintf("destination directory durability could not be confirmed: %v", err))
	}
	return checksum, warnings, nil
}

// Abort closes and removes the staging file. It is safe to call more than
// once and after Finish.
func (w *BackupExportWriter) Abort() {
	if w.tmp != nil {
		_ = w.tmp.Close()
	}
	if w.tmpPath != "" {
		_ = os.Remove(w.tmpPath)
	}
}
