// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/transport"
)

const apstoreIPCTimeout = 30 * time.Second
const backupImportValidationTimeout = 2 * time.Minute

type apstoreAdminClient struct {
	conn *transport.IPCClient
}

type apstoreAdminRequester interface {
	request(msg any, out any) error
	close()
}

var newApstoreAdminClientForCommand = func() (apstoreAdminRequester, error) {
	return newApstoreAdminClient()
}

var newApstoreAdminClientWithPassphraseForCommand = func(passphrase []byte) (apstoreAdminRequester, error) {
	return newApstoreAdminClientWithPassphrase(passphrase)
}

var initializeStoreForCommand = initializeStoreLocal

var newBackupImportTemplateValidationClientForCommand = newBackupImportTemplateValidationClient

func newBackupImportTemplateValidationClient() (*algod.Client, error) {
	if cfg, err := config.GetTEALCompileAlgod(); err == nil && cfg != nil && cfg.Server != "" {
		return algod.MakeClient(cfg.Server, cfg.Token)
	}
	return algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), algo.ResolveTEALCompileAlgodToken())
}

func newApstoreAdminClient() (*apstoreAdminClient, error) {
	conn := transport.NewIPC(config.IPCPath)
	if err := conn.Dial(); err != nil {
		return nil, err
	}
	client := &apstoreAdminClient{conn: conn}
	if err := client.authenticateAndUnlock(); err != nil {
		conn.Close()
		return nil, err
	}
	return client, nil
}

func newApstoreAdminClientWithPassphrase(passphrase []byte) (*apstoreAdminClient, error) {
	conn := transport.NewIPC(config.IPCPath)
	if err := conn.Dial(); err != nil {
		return nil, err
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
	passphrase := os.Getenv("TEST_PASSPHRASE")
	var passphraseBytes []byte
	if passphrase == "" {
		fmt.Print("Enter admin passphrase: ")
		var err error
		passphraseBytes, err = readPassword()
		if err != nil {
			return fmt.Errorf("failed to read admin passphrase: %w", err)
		}
		fmt.Println()
		defer crypto.ZeroBytes(passphraseBytes)
		passphrase = string(passphraseBytes)
	}
	return c.authenticateAndUnlockString(passphrase)
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
		return fmt.Errorf("signer is locked and could not unlock: %w", err)
	}
	if !result.Success {
		if result.Error != "" {
			return fmt.Errorf("signer is locked and could not unlock: %s", result.Error)
		}
		return fmt.Errorf("signer is locked and could not unlock")
	}
	return nil
}

func (c *apstoreAdminClient) request(msg any, out any) error {
	response, err := c.conn.SendAndReceive(msg, apstoreIPCTimeout)
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
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore backup import <archive-path>")
		}
		return cmdBackupImport(args[1])
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
		status := "unverified"
		if item.Verified {
			status = "verified"
		}
		fmt.Printf("%s  %s  %s  %s\n", item.FileName, backup.FormatFileSize(item.Size), status, item.Checksum)
	}
	return nil
}

func cmdBackupImport(source string) error {
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

	backupDir := keystorePaths().IdentityBackupsDir(productIdentityID())
	for _, dir := range []string{keystorePaths().BackupsRootDir(), backupDir} {
		if err := fsutil.MkdirAll(dir); err != nil {
			return fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	name := filepath.Base(source)
	dest := filepath.Join(backupDir, name)
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("managed backup already exists: %s", name)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to inspect backup import destination: %w", err)
	}

	tmp, err := os.CreateTemp(backupDir, ".import-*.tar.gz")
	if err != nil {
		return fmt.Errorf("failed to create backup import file: %w", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := copyFile(source, tmpPath); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, fsutil.StoreFilePerm); err != nil {
		return fmt.Errorf("failed to set backup archive permissions: %w", err)
	}
	if _, err := backup.StatManagedBackupArchive(tmpPath); err != nil {
		return codedError{code: "invalid_backup", message: fmt.Sprintf("failed to validate imported backup archive: %v", err)}
	}
	sourceRoot, cleanup, err := backup.PrepareRestoreSource(tmpPath)
	if err != nil {
		return codedError{code: "invalid_backup", message: fmt.Sprintf("failed to validate imported backup archive: %v", err)}
	}
	defer cleanup()
	if err := validateImportedBackupContents(sourceRoot); err != nil {
		return codedError{code: "invalid_backup", message: fmt.Sprintf("failed to validate imported backup contents: %v", err)}
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		return fmt.Errorf("failed to publish imported backup archive: %w", err)
	}
	if err := normalizeImportedBackupOwnership(backupDir, dest); err != nil {
		return fmt.Errorf("failed to normalize imported backup ownership: %w", err)
	}
	checksum, size, err := backup.FileSHA256(dest)
	if err != nil {
		return fmt.Errorf("failed to checksum imported backup archive: %w", err)
	}
	logInfof("backup imported: %s", name)
	logInfof("size: %s", backup.FormatFileSize(size))
	logInfof("checksum: %s", checksum)
	return nil
}

func validateImportedBackupContents(sourceRoot string) error {
	logInfof("import validation requires the export passphrase")
	fmt.Print("Enter export passphrase: ")
	exportPassphrase, err := readPromptedPassword()
	if err != nil {
		return fmt.Errorf("failed to read export passphrase: %w", err)
	}
	fmt.Println()
	defer crypto.ZeroBytes(exportPassphrase)
	if len(exportPassphrase) == 0 {
		return fmt.Errorf("export passphrase cannot be empty")
	}

	algodClient, err := newBackupImportTemplateValidationClientForCommand()
	if err != nil {
		return fmt.Errorf("failed to configure TEAL compiler client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), backupImportValidationTimeout)
	defer cancel()

	report, err := backup.DeepVerifyBackupWithOptions(sourceRoot, string(exportPassphrase), backup.DeepVerifyOptions{
		ValidateBundledTemplateBytecode: true,
		AlgodClient:                     algodClient,
		Context:                         ctx,
	})
	if err != nil {
		return err
	}
	if report.FailedFiles > 0 {
		for _, result := range report.Results {
			if !result.Valid {
				return fmt.Errorf("%d of %d key file(s) failed validation: %s: %s",
					report.FailedFiles, report.TotalFiles, result.FileName, result.Error)
			}
		}
		return fmt.Errorf("%d of %d key file(s) failed validation", report.FailedFiles, report.TotalFiles)
	}
	logInfof("backup contents verified: %d key file(s)", report.ValidFiles)
	return nil
}

func normalizeImportedBackupOwnership(backupDir, archivePath string) error {
	if currentEUID() != 0 {
		return nil
	}
	info, err := os.Stat(dataDirectory)
	if err != nil {
		return err
	}
	uid, gid, err := fileOwnerGroup(info)
	if err != nil {
		return err
	}
	for _, path := range []string{keystorePaths().BackupsRootDir(), backupDir, archivePath} {
		if err := os.Lchown(path, uid, gid); err != nil {
			return err
		}
	}
	return nil
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

	info, err := findManagedBackup(name)
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
	if err := copyFile(info.Path, destination); err != nil {
		return err
	}
	checksum, size, err := backup.FileSHA256(destination)
	if err != nil {
		return fmt.Errorf("failed to verify exported backup: %w", err)
	}
	if size != info.Size {
		return codedError{code: "verification_failed", message: fmt.Sprintf("exported backup size mismatch: got %d, want %d", size, info.Size)}
	}
	if info.Checksum != "" && checksum != info.Checksum {
		return codedError{code: "verification_failed", message: fmt.Sprintf("exported backup checksum mismatch: got %s, want %s", checksum, info.Checksum)}
	}
	logInfof("backup exported: %s", destination)
	logInfof("checksum: %s", checksum)
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

func findManagedBackup(name string) (protocol.BackupInfo, error) {
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return protocol.BackupInfo{}, err
	}
	defer client.close()
	return findManagedBackupWithClient(client, name)
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
	fmt.Print(prompt)
	passphrase, err := readPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	fmt.Println()
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}
	fmt.Print(confirmPrompt)
	confirm, err := readPassword()
	if err != nil {
		crypto.ZeroBytes(passphrase)
		return nil, fmt.Errorf("failed to read confirmation: %w", err)
	}
	defer crypto.ZeroBytes(confirm)
	fmt.Println()
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

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open managed backup: %w", err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create destination backup: %w", err)
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("failed to copy backup: %w", err)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("failed to sync destination backup: %w", err)
	}
	return nil
}
