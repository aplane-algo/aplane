// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestIPCBackupCreatesManagedArchive(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	svc := signerAdminServices{signer: server}
	gen := svc.GenerateKey(context.Background(), ir, adminproto.GenerateKeyRequest{KeyType: "ed25519"})
	if !gen.Success {
		t.Fatalf("GenerateKey() failed: %s", gen.Error)
	}

	recorder := &ipcJSONRecorderConn{}
	ipcServer := &IPCServer{signer: server}
	session := newBoundTestSession(ipcServer, recorder, ir)

	dispatchIPCMessage(t, session, protocol.BackupMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeBackup,
			ID:   "backup-test",
		},
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})

	msgs := recorder.messages(t)
	if len(msgs) != 1 {
		t.Fatalf("message count = %d, want 1", len(msgs))
	}
	if !reflectJSONSubset(msgs[0], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeBackupResult,
		"id":      "backup-test",
		"success": true,
	}) {
		t.Fatalf("backup response mismatch: %#v", msgs[0])
	}

	archivePath, _ := msgs[0]["archive_path"].(string)
	if archivePath == "" {
		t.Fatal("archive_path missing from backup response")
	}
	if !strings.HasSuffix(archivePath, ".tar.gz") {
		t.Fatalf("ArchivePath = %q, want .tar.gz suffix", archivePath)
	}
	if !strings.Contains(archivePath, filepath.Join("backups", auth.DefaultIdentityID)) {
		t.Fatalf("ArchivePath = %q, want managed backup directory", archivePath)
	}
	if _, err := os.Stat(archivePath); err != nil {
		t.Fatalf("backup archive stat error = %v", err)
	}

	extractDir := t.TempDir()
	if err := backup.ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatalf("ExtractTarGzArchive() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "README.md")); err != nil {
		t.Fatalf("README.md missing from backup archive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "apb", gen.Address+".apb")); err != nil {
		t.Fatalf("expected backup payload for generated key: %v", err)
	}
}

func TestIPCManagedBackupPreviewAndRestore(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	svc := signerAdminServices{signer: server}
	gen := svc.GenerateKey(context.Background(), ir, adminproto.GenerateKeyRequest{KeyType: "ed25519"})
	if !gen.Success {
		t.Fatalf("GenerateKey() failed: %s", gen.Error)
	}

	ipcServer := &IPCServer{signer: server}
	backupRecorder := &ipcJSONRecorderConn{}
	backupSession := newBoundTestSession(ipcServer, backupRecorder, ir)
	dispatchIPCMessage(t, backupSession, protocol.BackupMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeBackup,
			ID:   "backup-restore-test",
		},
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	backupMsgs := backupRecorder.messages(t)
	if len(backupMsgs) != 1 {
		t.Fatalf("backup message count = %d, want 1", len(backupMsgs))
	}
	archivePath, _ := backupMsgs[0]["archive_path"].(string)
	if archivePath == "" {
		t.Fatal("archive_path missing from backup response")
	}

	listRecorder := &ipcJSONRecorderConn{}
	listSession := newBoundTestSession(ipcServer, listRecorder, ir)
	dispatchIPCMessage(t, listSession, protocol.ListBackupsMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeListBackups,
			ID:   "list-backups-test",
		},
	})
	listMsgs := listRecorder.messages(t)
	if len(listMsgs) != 1 {
		t.Fatalf("list message count = %d, want 1", len(listMsgs))
	}
	if !reflectJSONSubset(listMsgs[0], map[string]any{
		"kind": string(protocol.MessageKindResponse),
		"type": protocol.MsgTypeBackupsList,
		"id":   "list-backups-test",
	}) {
		t.Fatalf("list backups response mismatch: %#v", listMsgs[0])
	}
	backups, _ := listMsgs[0]["backups"].([]any)
	if len(backups) != 1 {
		t.Fatalf("managed backup count = %d, want 1", len(backups))
	}
	backupInfo, ok := backups[0].(map[string]any)
	if !ok {
		t.Fatalf("backup entry has unexpected type: %#v", backups[0])
	}
	if backupInfo["path"] != archivePath {
		t.Fatalf("listed backup path = %#v, want %s", backupInfo["path"], archivePath)
	}

	previewRecorder := &ipcJSONRecorderConn{}
	previewSession := newBoundTestSession(ipcServer, previewRecorder, ir)
	dispatchIPCMessage(t, previewSession, protocol.PreviewRestoreMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypePreviewRestore,
			ID:   "preview-restore-test",
		},
		ArchivePath:      filepath.Base(archivePath),
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	previewMsgs := previewRecorder.messages(t)
	if len(previewMsgs) != 1 {
		t.Fatalf("preview message count = %d, want 1", len(previewMsgs))
	}
	if !reflectJSONSubset(previewMsgs[0], map[string]any{
		"kind": string(protocol.MessageKindResponse),
		"type": protocol.MsgTypeRestorePreview,
		"id":   "preview-restore-test",
	}) {
		t.Fatalf("preview restore response mismatch: %#v", previewMsgs[0])
	}
	previewKeys, _ := previewMsgs[0]["keys"].([]any)
	if len(previewKeys) != 1 {
		t.Fatalf("preview key count = %d, want 1", len(previewKeys))
	}
	previewKey, ok := previewKeys[0].(map[string]any)
	if !ok {
		t.Fatalf("preview key has unexpected type: %#v", previewKeys[0])
	}
	if previewKey["address"] != gen.Address || previewKey["already_exists"] != true {
		t.Fatalf("preview key = %#v, want generated address marked existing", previewKey)
	}

	del := svc.DeleteKey(ir, adminproto.DeleteKeyRequest{Address: gen.Address})
	if !del.Success {
		t.Fatalf("DeleteKey() failed: %s", del.Error)
	}
	if _, err := os.Stat(server.keyPaths.KeyFilePath(auth.DefaultIdentityID, gen.Address)); !os.IsNotExist(err) {
		t.Fatalf("deleted key stat err = %v, want not exist", err)
	}

	server.ipcServer = ipcServer
	activeRecorder := addActiveIdentitySession(t, ipcServer, auth.DefaultIdentityID)

	restoreRecorder := &ipcJSONRecorderConn{}
	restoreSession := newBoundTestSession(ipcServer, restoreRecorder, ir)
	dispatchIPCMessage(t, restoreSession, protocol.RestoreBackupMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRestoreBackup,
			ID:   "restore-backup-test",
		},
		ArchivePath:      filepath.Base(archivePath),
		Addresses:        []string{gen.Address},
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	restoreMsgs := restoreRecorder.messages(t)
	if len(restoreMsgs) != 1 {
		t.Fatalf("restore message count = %d, want 1", len(restoreMsgs))
	}
	if !reflectJSONSubset(restoreMsgs[0], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeRestoreBackupResult,
		"id":      "restore-backup-test",
		"success": true,
	}) {
		t.Fatalf("restore backup response mismatch: %#v", restoreMsgs[0])
	}
	restored, _ := restoreMsgs[0]["restored"].([]any)
	if len(restored) != 1 {
		t.Fatalf("restored key count = %d, want 1", len(restored))
	}
	if _, err := os.Stat(server.keyPaths.KeyFilePath(auth.DefaultIdentityID, gen.Address)); err != nil {
		t.Fatalf("restored key stat error = %v", err)
	}

	activeMsgs := activeRecorder.messages(t)
	if len(activeMsgs) != 1 {
		t.Fatalf("active notification count = %d, want 1 keys_changed notification", len(activeMsgs))
	}
	if !reflectJSONSubset(activeMsgs[0], map[string]any{
		"kind": string(protocol.MessageKindNotification),
		"type": protocol.MsgTypeKeysChanged,
	}) {
		t.Fatalf("active notification mismatch: %#v", activeMsgs[0])
	}
}

func TestIPCRestoreSkipsExistingKeyWithoutOverwrite(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	svc := signerAdminServices{signer: server}
	gen := svc.GenerateKey(context.Background(), ir, adminproto.GenerateKeyRequest{KeyType: "ed25519"})
	if !gen.Success {
		t.Fatalf("GenerateKey() failed: %s", gen.Error)
	}

	ipcServer := &IPCServer{signer: server}
	server.ipcServer = ipcServer
	activeRecorder := addActiveIdentitySession(t, ipcServer, auth.DefaultIdentityID)

	backupRecorder := &ipcJSONRecorderConn{}
	backupSession := newBoundTestSession(ipcServer, backupRecorder, ir)
	dispatchIPCMessage(t, backupSession, protocol.BackupMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeBackup,
			ID:   "backup-existing-test",
		},
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	backupMsgs := backupRecorder.messages(t)
	if len(backupMsgs) != 1 {
		t.Fatalf("backup message count = %d, want 1", len(backupMsgs))
	}
	archivePath, _ := backupMsgs[0]["archive_path"].(string)
	if archivePath == "" {
		t.Fatal("archive_path missing from backup response")
	}

	restoreRecorder := &ipcJSONRecorderConn{}
	restoreSession := newBoundTestSession(ipcServer, restoreRecorder, ir)
	dispatchIPCMessage(t, restoreSession, protocol.RestoreBackupMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRestoreBackup,
			ID:   "restore-existing-test",
		},
		ArchivePath:      filepath.Base(archivePath),
		Addresses:        []string{gen.Address},
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	restoreMsgs := restoreRecorder.messages(t)
	if len(restoreMsgs) != 1 {
		t.Fatalf("restore message count = %d, want 1", len(restoreMsgs))
	}
	if !reflectJSONSubset(restoreMsgs[0], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeRestoreBackupResult,
		"id":      "restore-existing-test",
		"success": true,
	}) {
		t.Fatalf("restore existing response mismatch: %#v", restoreMsgs[0])
	}
	restored, _ := restoreMsgs[0]["restored"].([]any)
	if len(restored) != 0 {
		t.Fatalf("restored key count = %d, want 0 without overwrite", len(restored))
	}
	skipped, _ := restoreMsgs[0]["skipped"].([]any)
	if len(skipped) != 1 {
		t.Fatalf("skipped key count = %d, want 1", len(skipped))
	}
	skippedKey, ok := skipped[0].(map[string]any)
	if !ok {
		t.Fatalf("skipped key has unexpected type: %#v", skipped[0])
	}
	if skippedKey["address"] != gen.Address || skippedKey["already_exists"] != true {
		t.Fatalf("skipped key = %#v, want existing generated address", skippedKey)
	}
	if activeMsgs := activeRecorder.messages(t); len(activeMsgs) != 0 {
		t.Fatalf("active notification count = %d, want 0 for skipped-only restore: %#v", len(activeMsgs), activeMsgs)
	}
}

func TestIPCRestorePreviewRateLimitsFailures(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	svc := signerAdminServices{signer: server}
	gen := svc.GenerateKey(context.Background(), ir, adminproto.GenerateKeyRequest{KeyType: "ed25519"})
	if !gen.Success {
		t.Fatalf("GenerateKey() failed: %s", gen.Error)
	}

	ipcServer := &IPCServer{signer: server}
	backupRecorder := &ipcJSONRecorderConn{}
	backupSession := newBoundTestSession(ipcServer, backupRecorder, ir)
	dispatchIPCMessage(t, backupSession, protocol.BackupMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeBackup,
			ID:   "backup-rate-limit-test",
		},
		ExportPassphrase: protocol.NewSensitiveBytes("correct-passphrase"),
	})
	backupMsgs := backupRecorder.messages(t)
	if len(backupMsgs) != 1 {
		t.Fatalf("backup message count = %d, want 1", len(backupMsgs))
	}
	archivePath, _ := backupMsgs[0]["archive_path"].(string)
	if archivePath == "" {
		t.Fatal("archive_path missing from backup response")
	}

	firstRecorder := &ipcJSONRecorderConn{}
	firstSession := newBoundTestSession(ipcServer, firstRecorder, ir)
	dispatchIPCMessage(t, firstSession, protocol.PreviewRestoreMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypePreviewRestore,
			ID:   "preview-wrong-passphrase",
		},
		ArchivePath:      filepath.Base(archivePath),
		ExportPassphrase: protocol.NewSensitiveBytes("wrong-passphrase"),
	})
	firstMsgs := firstRecorder.messages(t)
	if len(firstMsgs) != 1 {
		t.Fatalf("first preview message count = %d, want 1", len(firstMsgs))
	}
	if !reflectJSONSubset(firstMsgs[0], map[string]any{
		"kind": string(protocol.MessageKindResponse),
		"type": protocol.MsgTypeRestorePreview,
		"id":   "preview-wrong-passphrase",
	}) {
		t.Fatalf("first preview response mismatch: %#v", firstMsgs[0])
	}
	firstErrors, _ := firstMsgs[0]["errors"].([]any)
	if len(firstErrors) == 0 {
		t.Fatalf("first preview errors = %#v, want decrypt error", firstMsgs[0]["errors"])
	}
	firstError, ok := firstErrors[0].(map[string]any)
	if !ok {
		t.Fatalf("first preview error has unexpected type: %#v", firstErrors[0])
	}
	if _, leaked := firstError["address"]; leaked {
		t.Fatalf("wrong-passphrase preview leaked address %s in error %#v", gen.Address, firstError)
	}

	secondRecorder := &ipcJSONRecorderConn{}
	secondSession := newBoundTestSession(ipcServer, secondRecorder, ir)
	dispatchIPCMessage(t, secondSession, protocol.PreviewRestoreMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypePreviewRestore,
			ID:   "preview-rate-limited",
		},
		ArchivePath:      filepath.Base(archivePath),
		ExportPassphrase: protocol.NewSensitiveBytes("correct-passphrase"),
	})
	secondMsgs := secondRecorder.messages(t)
	if len(secondMsgs) != 1 {
		t.Fatalf("second preview message count = %d, want 1", len(secondMsgs))
	}
	if !reflectJSONSubset(secondMsgs[0], map[string]any{
		"kind": string(protocol.MessageKindResponse),
		"type": protocol.MsgTypeRestorePreview,
		"id":   "preview-rate-limited",
		"code": "restore_rate_limited",
	}) {
		t.Fatalf("second preview response mismatch: %#v", secondMsgs[0])
	}
}
