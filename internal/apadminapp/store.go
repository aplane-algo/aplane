// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/protocol"
)

const (
	backupImportUsage = "usage: apadmin backup import <archive-path>"
	restoreApplyUsage = "usage: apadmin restore apply <backup-id|name> [--address ADDRESS ...] [--replace-existing]"
)

// Store runs daemon-owned backup, restore, and passphrase workflows. Secret
// collection belongs to the command adapter so terminal and remote rules are
// shared across command families.
type Store struct {
	Client        Requester
	Streams       Streams
	ReadSecret    func(prompt string) ([]byte, error)
	ReadConfirmed func(prompt, confirmation string) ([]byte, error)
	Confirm       func(prompt string) bool
	Now           func() time.Time
}

func (s Store) normalized() Store {
	s.Streams = s.Streams.normalized()
	if s.ReadSecret == nil {
		s.ReadSecret = func(string) ([]byte, error) { return nil, fmt.Errorf("secret reader is required") }
	}
	if s.ReadConfirmed == nil {
		s.ReadConfirmed = func(string, string) ([]byte, error) { return nil, fmt.Errorf("confirmed secret reader is required") }
	}
	if s.Confirm == nil {
		s.Confirm = func(string) bool { return false }
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	return s
}

// StoreAuthMode validates the store command grammar before authentication.
func StoreAuthMode(command string, args []string) (AuthMode, error) {
	switch command {
	case "backup":
		if err := validateBackupArgs(args); err != nil {
			return AuthUnlock, err
		}
	case "restore":
		if err := validateRestoreArgs(args); err != nil {
			return AuthUnlock, err
		}
	case "changepass":
		if len(args) != 0 {
			return AuthUnlock, fmt.Errorf("usage: apadmin changepass")
		}
	default:
		return AuthUnlock, fmt.Errorf("unknown live store command %q", command)
	}
	return AuthUnlock, nil
}

func validateBackupArgs(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apadmin backup <create|import|list|export|delete>")
	}
	switch args[0] {
	case "create":
		if len(args) == 2 && args[1] == "all" {
			return nil
		}
		if len(args) == 3 && args[1] == "address" {
			return nil
		}
		return fmt.Errorf("usage: apadmin backup create <all|address ADDRESS>")
	case "import":
		if len(args) != 2 {
			return errors.New(backupImportUsage)
		}
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: apadmin backup list")
		}
	case "export":
		if len(args) != 3 {
			return fmt.Errorf("usage: apadmin backup export <backup-name|checksum> <destination-dir>")
		}
	case "delete":
		if len(args) != 2 {
			return fmt.Errorf("usage: apadmin backup delete <backup-id|name>")
		}
	default:
		return fmt.Errorf("usage: apadmin backup <create|import|list|export|delete>")
	}
	return nil
}

func validateRestoreArgs(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apadmin restore <preview|apply|rollback|reconcile>")
	}
	switch args[0] {
	case "preview":
		if len(args) != 2 {
			return fmt.Errorf("usage: apadmin restore preview <backup-id|name>")
		}
	case "apply":
		if len(args) < 2 {
			return errors.New(restoreApplyUsage)
		}
		for i := 2; i < len(args); i++ {
			switch args[i] {
			case "--replace-existing":
			case "--address":
				if i+1 >= len(args) {
					return errors.New(restoreApplyUsage)
				}
				i++
			default:
				return fmt.Errorf("unknown restore apply option: %s", args[i])
			}
		}
	case "rollback", "reconcile":
		if len(args) != 1 {
			return fmt.Errorf("usage: apadmin restore %s", args[0])
		}
	default:
		return fmt.Errorf("usage: apadmin restore <preview|apply|rollback|reconcile>")
	}
	return nil
}

// RunBackup executes one validated managed-backup command.
func (s Store) RunBackup(args []string) error {
	s = s.normalized()
	if s.Client == nil {
		return fmt.Errorf("admin requester is required")
	}
	if err := validateBackupArgs(args); err != nil {
		return err
	}
	switch args[0] {
	case "create":
		return s.backupCreate(args[1:])
	case "import":
		return s.backupImport(args[1])
	case "list":
		return s.backupList()
	case "export":
		return s.backupExport(args[1], args[2])
	case "delete":
		return s.backupDelete(args[1])
	default:
		panic("validated backup verb")
	}
}

func (s Store) backupCreate(args []string) error {
	var addresses []string
	if args[0] == "address" {
		addresses = []string{args[1]}
	}
	exportPassphrase, err := s.ReadConfirmed("Enter export passphrase (for backup encryption): ", "Confirm export passphrase: ")
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(exportPassphrase)
	var result protocol.BackupResultMessage
	if err := s.Client.Request(protocol.BackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeBackup, ID: s.requestID("backup-create")},
		ExportPassphrase: protocol.SensitiveBytes(exportPassphrase), Addresses: addresses,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("backup failed", result.Code, result.Error)
	}
	s.info("managed backup created: %s", result.ArchivePath)
	if result.ArchiveChecksum != "" {
		s.info("checksum: %s", result.ArchiveChecksum)
	}
	if result.ArchiveSize > 0 {
		s.info("size: %s", backup.FormatFileSize(result.ArchiveSize))
	}
	if result.KeyCount > 0 {
		s.info("keys: %d", result.KeyCount)
	}
	if result.Verified {
		s.info("verified: yes")
	}
	return nil
}

func (s Store) backupList() error {
	var result protocol.BackupsListMessage
	if err := s.Client.Request(protocol.ListBackupsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListBackups, ID: s.requestID("backup-list")},
	}, &result); err != nil {
		return err
	}
	if result.Error != "" {
		return resultError("list backups failed", result.Code, result.Error)
	}
	if len(result.Backups) == 0 {
		s.info("no managed backups found")
		return nil
	}
	for _, item := range result.Backups {
		_, _ = fmt.Fprintf(s.Streams.Stdout, "%s  %s  %s\n", item.FileName, backup.FormatFileSize(item.Size), item.Checksum)
	}
	return nil
}

func (s Store) backupImport(source string) error {
	if !backup.IsArchivePath(source) {
		return fmt.Errorf("backup source must end in .tar.gz or .tgz: %s", source)
	}
	info, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("backup source unavailable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("backup source must be a regular file, not a symlink: %s", source)
	}
	if _, err := backup.StatManagedBackupArchive(source); err != nil {
		return protocol.WithCode("invalid_backup", fmt.Errorf("failed to validate imported backup archive: %w", err))
	}
	exportPassphrase, err := s.ReadSecret("Enter export passphrase for daemon validation: ")
	if err != nil {
		return fmt.Errorf("failed to read backup export passphrase: %w", err)
	}
	defer crypto.ZeroBytes(exportPassphrase)
	checksum, size, err := backup.FileSHA256(source)
	if err != nil {
		return fmt.Errorf("failed to checksum backup source: %w", err)
	}
	name := filepath.Base(source)
	var begin protocol.BeginBackupImportResultMessage
	if err := s.Client.Request(protocol.BeginBackupImportMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeBeginBackupImport, ID: s.requestID("backup-import-begin")}, FileName: name,
	}, &begin); err != nil {
		return err
	}
	if !begin.Success {
		return resultError("backup import failed", begin.Code, begin.Error)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		var ignored protocol.AbortBackupImportResultMessage
		_ = s.Client.Request(protocol.AbortBackupImportMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAbortBackupImport, ID: s.requestID("backup-import-abort")}, UploadID: begin.UploadID,
		}, &ignored)
	}()
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	buffer := make([]byte, adminproto.BackupTransferChunkBytes)
	var offset int64
	for {
		n, readErr := file.Read(buffer)
		if n > 0 {
			var appended protocol.AppendBackupImportResultMessage
			if err := s.Client.Request(protocol.AppendBackupImportMessage{
				BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAppendBackupImport, ID: s.requestID("backup-import-append")},
				UploadID:    begin.UploadID, Offset: offset, Data: append([]byte(nil), buffer[:n]...),
			}, &appended); err != nil {
				return err
			}
			if !appended.Success {
				return resultError("backup import failed", appended.Code, appended.Error)
			}
			offset = appended.NextOffset
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	var commit protocol.CommitBackupImportResultMessage
	if err := s.Client.RequestWithTimeout(protocol.CommitBackupImportMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeCommitBackupImport, ID: s.requestID("backup-import-commit")},
		UploadID:    begin.UploadID, FileName: name, ExpectedSize: size, ExpectedSHA256: checksum,
		ExportPassphrase: protocol.SensitiveBytes(exportPassphrase),
	}, &commit, BackupCommitTimeout); err != nil {
		return err
	}
	if !commit.Success {
		return resultError("backup import failed", commit.Code, commit.Error)
	}
	committed = true
	if commit.Warning != "" {
		s.warn("backup import warning: %s", commit.Warning)
	}
	s.info("backup imported: %s", name)
	s.info("size: %s", backup.FormatFileSize(size))
	s.info("checksum: %s", checksum)
	return nil
}

func (s Store) backupDelete(name string) error {
	info, err := s.findBackup(name)
	if err != nil {
		return err
	}
	if !s.Confirm(fmt.Sprintf("Delete managed backup %s? [y/N]: ", info.FileName)) {
		return fmt.Errorf("delete cancelled")
	}
	var result protocol.DeleteBackupResultMessage
	if err := s.Client.Request(protocol.DeleteBackupMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDeleteBackup, ID: s.requestID("backup-delete")}, ArchivePath: info.FileName,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("delete backup failed", result.Code, result.Error)
	}
	s.info("managed backup deleted: %s", info.FileName)
	return nil
}

func (s Store) findBackup(name string) (protocol.BackupInfo, error) {
	var result protocol.BackupsListMessage
	if err := s.Client.Request(protocol.ListBackupsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListBackups, ID: s.requestID("backup-find")},
	}, &result); err != nil {
		return protocol.BackupInfo{}, err
	}
	if result.Error != "" {
		return protocol.BackupInfo{}, resultError("list backups failed", result.Code, result.Error)
	}
	var checksumMatch *protocol.BackupInfo
	for _, item := range result.Backups {
		if item.FileName == name || item.Path == name {
			return item, nil
		}
		if item.Checksum != "" && item.Checksum == name {
			if checksumMatch != nil {
				return protocol.BackupInfo{}, fmt.Errorf("managed backup checksum matches multiple archives: %s", name)
			}
			matched := item
			checksumMatch = &matched
		}
	}
	if checksumMatch != nil {
		return *checksumMatch, nil
	}
	return protocol.BackupInfo{}, fmt.Errorf("managed backup not found: %s", name)
}

func (s Store) backupExport(name, destinationDir string) error {
	if backup.IsArchivePath(destinationDir) {
		return fmt.Errorf("backup export destination must be a directory, not an archive path: %s", destinationDir)
	}
	destinationExists := false
	if info, err := os.Stat(destinationDir); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to inspect backup export destination directory: %w", err)
		}
	} else if !info.IsDir() {
		return fmt.Errorf("backup export destination is not a directory: %s", destinationDir)
	} else {
		destinationExists = true
	}
	info, err := s.findBackup(name)
	if err != nil {
		return err
	}
	fileName := filepath.Base(info.FileName)
	if fileName == "." || fileName == string(filepath.Separator) || fileName != info.FileName {
		return fmt.Errorf("managed backup has invalid filename: %s", info.FileName)
	}
	if !destinationExists {
		if err := os.MkdirAll(destinationDir, 0o700); err != nil {
			return fmt.Errorf("failed to create backup export destination directory: %w", err)
		}
	}
	destination := filepath.Join(destinationDir, fileName)
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("backup export destination already exists: %s", destination)
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(destinationDir, ".aplane-backup-export-*.part")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = tmp.Close(); _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	var offset int64
	for {
		var chunk protocol.BackupChunkMessage
		if err := s.Client.Request(protocol.ReadBackupChunkMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeReadBackupChunk, ID: s.requestID("backup-export-chunk")},
			FileName:    info.FileName, Offset: offset,
		}, &chunk); err != nil {
			return err
		}
		if !chunk.Success {
			return resultError("backup export failed", chunk.Code, chunk.Error)
		}
		if chunk.Offset != offset {
			return fmt.Errorf("backup export returned offset %d, expected %d", chunk.Offset, offset)
		}
		if len(chunk.Data) > 0 {
			if _, err := tmp.Write(chunk.Data); err != nil {
				return err
			}
			offset += int64(len(chunk.Data))
		}
		if chunk.EOF {
			break
		}
		if len(chunk.Data) == 0 {
			return fmt.Errorf("backup export returned empty non-final chunk")
		}
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	checksum, size, err := backup.FileSHA256(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to verify exported backup: %w", err)
	}
	if size != info.Size {
		return protocol.WithCode("verification_failed", fmt.Errorf("exported backup size mismatch: got %d, want %d", size, info.Size))
	}
	if info.Checksum != "" && checksum != info.Checksum {
		return protocol.WithCode("verification_failed", fmt.Errorf("exported backup checksum mismatch: got %s, want %s", checksum, info.Checksum))
	}
	publication, err := publishBackupExportNoReplace(tmpPath, destination)
	if err != nil {
		return err
	}
	if err := fsutil.SyncDir(destinationDir); err != nil {
		publication.Warnings = append(publication.Warnings, fmt.Sprintf("destination directory durability could not be confirmed: %v", err))
	}
	for _, warning := range publication.Warnings {
		s.warn("backup export warning: %s", warning)
	}
	s.info("backup exported: %s", destination)
	s.info("checksum: %s", checksum)
	return nil
}

// RunRestore executes one validated managed-restore command.
func (s Store) RunRestore(args []string) error {
	s = s.normalized()
	if s.Client == nil {
		return fmt.Errorf("admin requester is required")
	}
	if err := validateRestoreArgs(args); err != nil {
		return err
	}
	switch args[0] {
	case "preview":
		secret, err := s.ReadSecret("Enter export passphrase (to decrypt backup files): ")
		if err != nil {
			return err
		}
		defer crypto.ZeroBytes(secret)
		return s.restorePreview(args[1], secret)
	case "apply":
		return s.restoreApply(args[1:])
	case "rollback":
		return s.restoreRollback()
	case "reconcile":
		return s.restoreReconcile()
	default:
		panic("validated restore verb")
	}
}

func (s Store) restorePreview(name string, secret []byte) error {
	var result protocol.RestorePreviewMessage
	if err := s.Client.Request(protocol.PreviewRestoreMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePreviewRestore, ID: s.requestID("restore-preview")},
		ArchivePath: name, ExportPassphrase: protocol.SensitiveBytes(secret),
	}, &result); err != nil {
		return err
	}
	s.renderRestorePreview(result)
	if result.Error != "" {
		return resultError("restore preview failed", result.Code, result.Error)
	}
	if len(result.Errors) > 0 {
		return fmt.Errorf("restore preview found %d error(s)", len(result.Errors))
	}
	return nil
}

func (s Store) restoreApply(args []string) error {
	name := args[0]
	var addresses []string
	replaceExisting := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--replace-existing":
			replaceExisting = true
		case "--address":
			addresses = append(addresses, args[i+1])
			i++
		}
	}
	secret, err := s.ReadSecret("Enter export passphrase (to decrypt backup files): ")
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(secret)
	s.info("restored credentials will use the destination's current policy and configuration")
	var result protocol.RestoreBackupResultMessage
	if err := s.Client.Request(protocol.RestoreBackupMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackup, ID: s.requestID("restore")},
		ArchivePath: name, Addresses: addresses, ExportPassphrase: protocol.SensitiveBytes(secret), ReplaceExisting: replaceExisting,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		for _, conflict := range result.Conflicts {
			s.warn("credential conflict: %s (%s, %s): %s", conflict.Selector, conflict.Category, conflict.KeyType, conflict.Reason)
		}
		return resultError("credential restore failed", result.Code, result.Error)
	}
	s.info("restored %d credential(s); %d already identical", len(result.Restored), len(result.Identical))
	if result.GenerationID != "" {
		s.info("generation: %s", result.GenerationID)
	}
	return nil
}

func (s Store) restoreRollback() error {
	if !s.Confirm("Roll back the latest clean credential restore? [y/N]: ") {
		return fmt.Errorf("rollback cancelled")
	}
	var result protocol.RollbackRestoreResultMessage
	if err := s.Client.Request(protocol.RollbackRestoreMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRollbackRestore, ID: s.requestID("restore-rollback")},
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("credential restore rollback failed", result.Code, result.Error)
	}
	s.info("rolled back latest credential restore into generation %s", result.GenerationID)
	return nil
}

func (s Store) restoreReconcile() error {
	var result protocol.ReconcileStoreResultMessage
	if err := s.Client.Request(protocol.ReconcileStoreMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeReconcileStore, ID: s.requestID("store-reconcile")},
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("store reconciliation failed", result.Code, result.Error)
	}
	s.info("store reconciled: generation %s, state %s", result.GenerationID, result.State)
	return nil
}

func (s Store) renderRestorePreview(result protocol.RestorePreviewMessage) {
	if result.ArchivePath != "" {
		s.info("restore preview: %s", result.ArchivePath)
	}
	for _, key := range result.Keys {
		status := "new"
		if key.AlreadyExists {
			status = "exists"
		}
		if key.Error != "" {
			status = "error: " + key.Error
		}
		parts := []string{key.Address}
		if key.KeyType != "" {
			parts = append(parts, displayKeyType(key.KeyType))
		}
		parts = append(parts, status)
		_, _ = fmt.Fprintf(s.Streams.Stdout, "  %s\n", strings.Join(parts, "  "))
	}
	for _, item := range result.Errors {
		if item.Address != "" {
			s.warn("%s: %s", item.Address, item.Error)
		} else {
			s.warn("%s", item.Error)
		}
	}
}

// ChangePassphrase sends an already-confirmed passphrase transition. The
// caller must authenticate this Store's Client with current first.
func (s Store) ChangePassphrase(current, next []byte) error {
	s = s.normalized()
	if s.Client == nil {
		return fmt.Errorf("admin requester is required")
	}
	if len(current) == 0 || len(next) == 0 {
		return fmt.Errorf("current and new passphrases are required")
	}
	message := protocol.ChangeStorePassphraseMessage{
		BaseMessage:       protocol.BaseMessage{Type: protocol.MsgTypeChangeStorePass, ID: s.requestID("changepass")},
		CurrentPassphrase: protocol.SensitiveBytes(append([]byte(nil), current...)),
		NewPassphrase:     protocol.SensitiveBytes(append([]byte(nil), next...)),
	}
	defer message.CurrentPassphrase.Zero()
	defer message.NewPassphrase.Zero()
	var result protocol.ChangeStorePassphraseResultMessage
	if err := s.Client.Request(message, &result); err != nil {
		return err
	}
	if !result.Success {
		if result.HelperWarning != "" {
			s.warn("%s", result.HelperWarning)
		}
		if result.RootCommitted {
			s.warn("the new passphrase is authoritative despite the incomplete operation")
			if result.RotationPending {
				s.warn("unlock with the new passphrase to resume the pending rotation")
			}
		}
		return resultError("passphrase change failed", result.Code, result.Error)
	}
	s.info("passphrase change complete")
	if result.KeysMigrated > 0 {
		s.info("  - %d key file(s) migrated", result.KeysMigrated)
	}
	if result.TemplatesMigrated > 0 {
		s.info("  - %d template file(s) migrated", result.TemplatesMigrated)
	}
	if result.PolicySidecarsMigrated > 0 {
		s.info("  - %d policy sidecar(s) re-signed", result.PolicySidecarsMigrated)
	}
	if result.NodeRoleSidecarsMigrated > 0 {
		s.info("  - %d node role sidecar(s) re-signed", result.NodeRoleSidecarsMigrated)
	}
	s.info("  - keystore metadata updated")
	if result.HelperWarning != "" {
		s.warn("%s", result.HelperWarning)
	}
	if result.PriorGenerations > 0 {
		s.warn("%d prior generation(s) remain readable under historical key terms", result.PriorGenerations)
		s.warn("run 'apstore generations prune --all-priors' when rollback retention is no longer required")
	}
	return nil
}

func (s Store) requestID(prefix string) string {
	return fmt.Sprintf("apadmin-%s-%d", prefix, s.Now().UnixNano())
}

func (s Store) info(format string, args ...any) {
	_, _ = fmt.Fprintf(s.Streams.Stderr, format+"\n", args...)
}

func (s Store) warn(format string, args ...any) {
	_, _ = fmt.Fprintf(s.Streams.Stderr, "warning: "+format+"\n", args...)
}

type backupExportPublication struct{ Warnings []string }

func publishBackupExportNoReplace(tmpPath, destination string) (backupExportPublication, error) {
	return publishBackupExportNoReplaceWith(tmpPath, destination, renameBackupExportNoReplace, os.Link, os.Remove)
}

func publishBackupExportNoReplaceWith(
	tmpPath, destination string,
	renameNoReplace func(string, string) error,
	link func(string, string) error,
	remove func(string) error,
) (backupExportPublication, error) {
	err := renameNoReplace(tmpPath, destination)
	if err == nil {
		return backupExportPublication{}, nil
	}
	if errors.Is(err, os.ErrExist) {
		return backupExportPublication{}, fmt.Errorf("backup export destination already exists: %s", destination)
	}
	if !backupExportNoReplaceUnsupported(err) {
		return backupExportPublication{}, fmt.Errorf("publish backup export: %w", err)
	}
	if linkErr := link(tmpPath, destination); linkErr != nil {
		if errors.Is(linkErr, os.ErrExist) {
			return backupExportPublication{}, fmt.Errorf("backup export destination already exists: %s", destination)
		}
		return backupExportPublication{}, fmt.Errorf("publish backup export: destination filesystem supports neither no-replace rename nor hard-link publication: %w", linkErr)
	}
	publication := backupExportPublication{}
	if removeErr := remove(tmpPath); removeErr != nil {
		publication.Warnings = append(publication.Warnings, fmt.Sprintf("export is committed, but staging file %s could not be removed: %v", tmpPath, removeErr))
	}
	return publication, nil
}
