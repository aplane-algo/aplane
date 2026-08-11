// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/transport"
)

const (
	apstoreIPCTimeout             = 30 * time.Second
	apstoreBackupCommitIPCTimeout = 30 * time.Minute
)

const importUsage = "usage: apstore backup import <archive-path>"

type apstoreAdminClient struct {
	conn *transport.IPCClient
}

var adminPassphrasePromptOutput io.Writer = os.Stderr
var backupPassphrasePromptOutput io.Writer = os.Stderr
var readAdminPassphrase = readPassword

type apstoreAdminRequester interface {
	request(msg any, out any) error
	requestWithTimeout(msg any, out any, timeout time.Duration) error
	close()
}

var newApstoreAdminClientForCommand = func() (apstoreAdminRequester, error) {
	return newApstoreAdminClient()
}

var newApstoreReadOnlyAdminClientForCommand = func() (apstoreAdminRequester, error) {
	return newApstoreReadOnlyAdminClient()
}

var newApstoreAdminClientWithPassphraseForCommand = func(passphrase []byte) (apstoreAdminRequester, error) {
	return newApstoreAdminClientWithPassphrase(passphrase)
}

var initializeStoreForCommand = initializeStoreLocal

func apstoreIPCPath() string {
	if adminSocketPath != "" {
		return adminSocketPath
	}
	return config.IPCPath
}

func newApstoreAdminClient() (*apstoreAdminClient, error) {
	conn := transport.NewIPC(apstoreIPCPath())
	if err := conn.Dial(); err != nil {
		return nil, codedError{code: apstoreCodeIPCUnavailable, message: err.Error()}
	}
	client := &apstoreAdminClient{conn: conn}
	if err := client.authenticateAndUnlock(); err != nil {
		conn.Close()
		return nil, err
	}
	return client, nil
}

func newApstoreReadOnlyAdminClient() (*apstoreAdminClient, error) {
	conn := transport.NewIPC(apstoreIPCPath())
	if err := conn.Dial(); err != nil {
		return nil, codedError{code: apstoreCodeIPCUnavailable, message: err.Error()}
	}
	client := &apstoreAdminClient{conn: conn}
	if err := client.authenticateOnly(); err != nil {
		conn.Close()
		return nil, err
	}
	return client, nil
}

func newApstoreAdminClientWithPassphrase(passphrase []byte) (*apstoreAdminClient, error) {
	conn := transport.NewIPC(apstoreIPCPath())
	if err := conn.Dial(); err != nil {
		return nil, codedError{code: apstoreCodeIPCUnavailable, message: err.Error()}
	}
	client := &apstoreAdminClient{conn: conn}
	if err := client.authenticateAndUnlockWithPassphrase(passphrase); err != nil {
		conn.Close()
		return nil, err
	}
	return client, nil
}

func (c *apstoreAdminClient) close() {
	if c != nil && c.conn != nil {
		c.conn.Close()
	}
}

func (c *apstoreAdminClient) authenticateAndUnlock() error {
	passphrase, clear, err := readApstoreAdminPassphrase()
	if err != nil {
		return err
	}
	defer clear()
	return c.authenticateAndUnlockString(passphrase)
}

func (c *apstoreAdminClient) authenticateOnly() error {
	passphrase, clear, err := readApstoreAdminPassphrase()
	if err != nil {
		return err
	}
	defer clear()
	return c.conn.AuthenticateOnly(passphrase, apstoreIPCTimeout)
}

func readApstoreAdminPassphrase() (string, func(), error) {
	passphrase := os.Getenv("TEST_PASSPHRASE")
	var passphraseBytes []byte
	if passphrase == "" {
		var err error
		passphraseBytes, err = promptForAdminPassphrase()
		if err != nil {
			return "", func() {}, fmt.Errorf("failed to read admin passphrase: %w", err)
		}
		passphrase = string(passphraseBytes)
	}
	return passphrase, func() { crypto.ZeroBytes(passphraseBytes) }, nil
}

func promptForAdminPassphrase() ([]byte, error) {
	_, _ = fmt.Fprint(adminPassphrasePromptOutput, "Enter admin passphrase: ")
	passphrase, err := readAdminPassphrase()
	_, _ = fmt.Fprintln(adminPassphrasePromptOutput)
	return passphrase, err
}

func (c *apstoreAdminClient) authenticateAndUnlockWithPassphrase(passphrase []byte) error {
	if len(passphrase) == 0 {
		return fmt.Errorf("admin passphrase cannot be empty")
	}
	return c.authenticateAndUnlockString(string(passphrase))
}

func (c *apstoreAdminClient) authenticateAndUnlockString(passphrase string) error {
	if err := c.conn.Authenticate(passphrase, apstoreIPCTimeout); err != nil {
		return err
	}
	status, err := c.conn.WaitForStatus(apstoreIPCTimeout)
	if err != nil {
		return err
	}
	if status.State != "locked" {
		return nil
	}
	result, err := c.conn.Unlock(passphrase, apstoreIPCTimeout)
	if err != nil {
		return protocol.WithCode(protocol.ErrCodeUnlockFailed, fmt.Errorf("signer is locked and could not unlock: %w", err))
	}
	if !result.Success {
		code := result.Code
		if code == "" {
			code = protocol.ErrCodeUnlockFailed
		}
		if result.Error != "" {
			return protocol.WithCode(code, fmt.Errorf("signer is locked and could not unlock: %s", result.Error))
		}
		return protocol.WithCode(code, fmt.Errorf("signer is locked and could not unlock"))
	}
	return nil
}

func (c *apstoreAdminClient) request(msg any, out any) error {
	return c.requestWithTimeout(msg, out, apstoreIPCTimeout)
}

func (c *apstoreAdminClient) requestWithTimeout(msg any, out any, timeout time.Duration) error {
	response, err := c.conn.SendAndReceive(msg, timeout)
	if err != nil {
		return err
	}
	var base protocol.BaseMessage
	if err := json.Unmarshal(response, &base); err != nil {
		return fmt.Errorf("failed to decode response envelope: %w", err)
	}
	if base.Type == protocol.MsgTypeError {
		var errMsg protocol.ErrorMessage
		if err := json.Unmarshal(response, &errMsg); err != nil {
			return fmt.Errorf("failed to decode error response: %w", err)
		}
		code := errMsg.Code
		if code == "" {
			code = protocol.IPCErrorCode(errMsg.Error)
		}
		return codedError{code: code, message: errMsg.Error}
	}
	if err := json.Unmarshal(response, out); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}

func cmdBackupManaged(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore backup <create|import|list|export|delete>")
	}
	switch args[0] {
	case "create":
		return cmdBackupCreate(args[1:])
	case "import":
		return cmdBackupImport(args[1:])
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: apstore backup list")
		}
		return cmdBackupList()
	case "export":
		if len(args) != 3 {
			return fmt.Errorf("usage: apstore backup export <backup-name|checksum> <destination-dir>")
		}
		return cmdBackupExport(args[1], args[2])
	case "delete":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore backup delete <backup-id|name>")
		}
		return cmdBackupDelete(args[1])
	default:
		return fmt.Errorf("usage: apstore backup <create|import|list|export|delete>")
	}
}

func cmdBackupCreate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore backup create <all|address ADDRESS>")
	}
	var addresses []string
	switch args[0] {
	case "all":
		if len(args) != 1 {
			return fmt.Errorf("usage: apstore backup create all")
		}
	case "address":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore backup create address <ADDRESS>")
		}
		addresses = []string{args[1]}
	default:
		return fmt.Errorf("usage: apstore backup create <all|address ADDRESS>")
	}

	exportPassphrase, err := promptConfirmedPassphrase("Enter export passphrase (for backup encryption): ", "Confirm export passphrase: ")
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(exportPassphrase)

	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()

	var result protocol.BackupResultMessage
	err = client.request(protocol.BackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeBackup, ID: newApstoreRequestID("backup-create")},
		ExportPassphrase: protocol.SensitiveBytes(exportPassphrase),
		Addresses:        addresses,
	}, &result)
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("backup failed", result.Code, result.Error)
	}
	logInfof("managed backup created: %s", result.ArchivePath)
	if result.ArchiveChecksum != "" {
		logInfof("checksum: %s", result.ArchiveChecksum)
	}
	if result.ArchiveSize > 0 {
		logInfof("size: %s", backup.FormatFileSize(result.ArchiveSize))
	}
	if result.KeyCount > 0 {
		logInfof("keys: %d", result.KeyCount)
	}
	if result.Verified {
		logInfof("verified: yes")
	}
	return nil
}

func cmdBackupList() error {
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()

	var result protocol.BackupsListMessage
	err = client.request(protocol.ListBackupsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListBackups, ID: newApstoreRequestID("backup-list")},
	}, &result)
	if err != nil {
		return err
	}
	if result.Error != "" {
		return resultError("list backups failed", result.Code, result.Error)
	}
	if len(result.Backups) == 0 {
		logInfof("no managed backups found")
		return nil
	}
	for _, item := range result.Backups {
		fmt.Printf("%s  %s  %s\n", item.FileName, backup.FormatFileSize(item.Size), item.Checksum)
	}
	return nil
}

func cmdBackupImport(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("%s", importUsage)
	}
	source := args[0]
	if !backup.IsArchivePath(source) {
		return fmt.Errorf("backup source must end in .tar.gz or .tgz: %s", source)
	}
	info, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("backup source unavailable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("backup source must be a regular file, not a symlink: %s", source)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("backup source must be a regular file: %s", source)
	}

	name := filepath.Base(source)
	if _, err := backup.StatManagedBackupArchive(source); err != nil {
		return codedError{code: "invalid_backup", message: fmt.Sprintf("failed to validate imported backup archive: %v", err)}
	}
	exportPassphrase, err := readBackupImportPassphrase()
	if err != nil {
		return codedError{code: "invalid_backup", message: fmt.Sprintf("failed to read backup export passphrase: %v", err)}
	}
	defer crypto.ZeroBytes(exportPassphrase)
	checksum, size, err := backup.FileSHA256(source)
	if err != nil {
		return fmt.Errorf("failed to checksum backup source: %w", err)
	}
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	var begin protocol.BeginBackupImportResultMessage
	if err := client.request(protocol.BeginBackupImportMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeBeginBackupImport, ID: newApstoreRequestID("backup-import-begin")},
		FileName:    name,
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
		_ = client.request(protocol.AbortBackupImportMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAbortBackupImport, ID: newApstoreRequestID("backup-import-abort")},
			UploadID:    begin.UploadID,
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
			if err := client.request(protocol.AppendBackupImportMessage{
				BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAppendBackupImport, ID: newApstoreRequestID("backup-import-append")},
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
	// Commit performs bounded archive extraction and passphrase-based deep
	// verification in the daemon. It is deliberately synchronous, but it must
	// not inherit the short timeout used by ordinary admin requests.
	if err := client.requestWithTimeout(protocol.CommitBackupImportMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeCommitBackupImport, ID: newApstoreRequestID("backup-import-commit")},
		UploadID:    begin.UploadID, FileName: name, ExpectedSize: size, ExpectedSHA256: checksum,
		ExportPassphrase: protocol.SensitiveBytes(exportPassphrase),
	}, &commit, apstoreBackupCommitIPCTimeout); err != nil {
		return err
	}
	if !commit.Success {
		return resultError("backup import failed", commit.Code, commit.Error)
	}
	committed = true
	logInfof("backup imported: %s", name)
	logInfof("size: %s", backup.FormatFileSize(size))
	logInfof("checksum: %s", checksum)
	return nil
}

func readBackupImportPassphrase() ([]byte, error) {
	logInfof("daemon validation requires the export passphrase")
	_, _ = fmt.Fprint(backupPassphrasePromptOutput, "Enter export passphrase: ")
	exportPassphrase, err := readPromptedPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to read export passphrase: %w", err)
	}
	_, _ = fmt.Fprintln(backupPassphrasePromptOutput)
	if len(exportPassphrase) == 0 {
		return nil, fmt.Errorf("export passphrase cannot be empty")
	}
	return exportPassphrase, nil
}

func cmdBackupExport(name, destinationDir string) error {
	if backup.IsArchivePath(destinationDir) {
		return fmt.Errorf("backup export destination must be a directory, not an archive path: %s", destinationDir)
	}

	destinationDirExists := false
	if st, err := os.Stat(destinationDir); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to inspect backup export destination directory: %w", err)
		}
	} else if !st.IsDir() {
		return fmt.Errorf("backup export destination is not a directory: %s", destinationDir)
	} else {
		destinationDirExists = true
	}

	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()
	info, err := findManagedBackupWithClient(client, name)
	if err != nil {
		return err
	}
	fileName := filepath.Base(info.FileName)
	if fileName == "." || fileName == string(filepath.Separator) || fileName != info.FileName {
		return fmt.Errorf("managed backup has invalid filename: %s", info.FileName)
	}

	if !destinationDirExists {
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
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	var offset int64
	for {
		var chunk protocol.BackupChunkMessage
		if err := client.request(protocol.ReadBackupChunkMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeReadBackupChunk, ID: newApstoreRequestID("backup-export-chunk")},
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
		return codedError{code: "verification_failed", message: fmt.Sprintf("exported backup size mismatch: got %d, want %d", size, info.Size)}
	}
	if info.Checksum != "" && checksum != info.Checksum {
		return codedError{code: "verification_failed", message: fmt.Sprintf("exported backup checksum mismatch: got %s, want %s", checksum, info.Checksum)}
	}
	if err := publishBackupExportNoReplace(tmpPath, destination); err != nil {
		return err
	}
	if err := fsutil.SyncDir(destinationDir); err != nil {
		return err
	}
	logInfof("backup exported: %s", destination)
	logInfof("checksum: %s", checksum)
	return nil
}

func publishBackupExportNoReplace(tmpPath, destination string) error {
	return publishBackupExportNoReplaceWith(tmpPath, destination, renameBackupExportNoReplace)
}

func publishBackupExportNoReplaceWith(tmpPath, destination string, renameNoReplace func(string, string) error) error {
	err := renameNoReplace(tmpPath, destination)
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("backup export destination already exists: %s", destination)
	}
	if !backupExportNoReplaceUnsupported(err) {
		return fmt.Errorf("publish backup export: %w", err)
	}

	// The staging file is created in the destination directory, so a hard link
	// provides an atomic no-replace fallback without a cross-filesystem case.
	// Do not fall back to Lstat followed by Rename: that would reintroduce the
	// overwrite race this publication boundary exists to prevent.
	if linkErr := os.Link(tmpPath, destination); linkErr != nil {
		if errors.Is(linkErr, os.ErrExist) {
			return fmt.Errorf("backup export destination already exists: %s", destination)
		}
		return fmt.Errorf(
			"publish backup export: destination filesystem supports neither no-replace rename nor hard-link publication: %w",
			linkErr,
		)
	}
	if removeErr := os.Remove(tmpPath); removeErr != nil {
		return fmt.Errorf("backup export published but failed to remove staging file %s: %w", tmpPath, removeErr)
	}
	return nil
}

func cmdBackupDelete(name string) error {
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return err
	}
	defer client.close()

	info, err := findManagedBackupWithClient(client, name)
	if err != nil {
		return err
	}
	if !confirmYesNo(fmt.Sprintf("Delete managed backup %s?", info.FileName)) {
		return fmt.Errorf("delete cancelled")
	}

	var result protocol.DeleteBackupResultMessage
	err = client.request(protocol.DeleteBackupMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDeleteBackup, ID: newApstoreRequestID("backup-delete")},
		ArchivePath: info.FileName,
	}, &result)
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("delete backup failed", result.Code, result.Error)
	}
	logInfof("managed backup deleted: %s", info.FileName)
	return nil
}

func findManagedBackupWithClient(client apstoreAdminRequester, name string) (protocol.BackupInfo, error) {
	var result protocol.BackupsListMessage
	err := client.request(protocol.ListBackupsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListBackups, ID: newApstoreRequestID("backup-find")},
	}, &result)
	if err != nil {
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

func promptConfirmedPassphrase(prompt, confirmPrompt string) ([]byte, error) {
	_, _ = fmt.Fprint(backupPassphrasePromptOutput, prompt)
	passphrase, err := readPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	_, _ = fmt.Fprintln(backupPassphrasePromptOutput)
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}
	_, _ = fmt.Fprint(backupPassphrasePromptOutput, confirmPrompt)
	confirm, err := readPassword()
	if err != nil {
		crypto.ZeroBytes(passphrase)
		return nil, fmt.Errorf("failed to read confirmation: %w", err)
	}
	defer crypto.ZeroBytes(confirm)
	_, _ = fmt.Fprintln(backupPassphrasePromptOutput)
	if string(passphrase) != string(confirm) {
		crypto.ZeroBytes(passphrase)
		return nil, fmt.Errorf("passphrases do not match")
	}
	return passphrase, nil
}

func newApstoreRequestID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func resultError(prefix, code, message string) error {
	if message == "" {
		message = "operation failed"
	}
	return codedError{prefix: prefix, code: code, message: message}
}
