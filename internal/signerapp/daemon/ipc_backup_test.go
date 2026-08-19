// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestIPCBackupCreatesManagedArchive(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.productIdentityRuntime()
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	svc := signerAdminServices{signer: server}
	gen := svc.keyApp().GenerateKey(context.Background(), ir, adminproto.GenerateKeyRequest{KeyType: "ed25519"})
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
	if archivePath != filepath.Base(archivePath) {
		t.Fatalf("ArchivePath = %q, want basename-only protocol value", archivePath)
	}
	managedArchivePath := filepath.Join(ir.KeyPaths().ProductBackupsDir(), archivePath)
	if _, err := os.Stat(managedArchivePath); err != nil {
		t.Fatalf("backup archive stat error = %v", err)
	}

	extractDir := t.TempDir()
	if err := backup.ExtractTarGzArchive(managedArchivePath, extractDir); err != nil {
		t.Fatalf("ExtractTarGzArchive() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "README.md")); err != nil {
		t.Fatalf("README.md missing from backup archive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "apb", gen.Address+".apb")); err != nil {
		t.Fatalf("expected backup payload for generated key: %v", err)
	}
}

func TestIPCManagedBackupPreviewAndDirectRestore(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productIdentityRuntime()
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}
	svc := signerAdminServices{signer: server}
	generated := svc.keyApp().GenerateKey(context.Background(), ir, adminproto.GenerateKeyRequest{KeyType: "ed25519"})
	if !generated.Success {
		t.Fatalf("GenerateKey() = %+v", generated)
	}
	ipcServer := &IPCServer{signer: server}
	backupRecorder := &ipcJSONRecorderConn{}
	dispatchIPCMessage(t, newBoundTestSession(ipcServer, backupRecorder, ir), protocol.BackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeBackup, ID: "backup-direct"},
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	backupMessages := backupRecorder.messages(t)
	archivePath, _ := backupMessages[0]["archive_path"].(string)
	if archivePath == "" {
		t.Fatalf("backup response = %#v", backupMessages)
	}
	if result := svc.keyApp().DeleteKey(ir, adminproto.DeleteKeyRequest{Address: generated.Address}); !result.Success {
		t.Fatalf("DeleteKey() = %+v", result)
	}
	restoreRecorder := &ipcJSONRecorderConn{}
	dispatchIPCMessage(t, newBoundTestSession(ipcServer, restoreRecorder, ir), protocol.RestoreBackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackup, ID: "restore-direct"},
		ArchivePath:      filepath.Base(archivePath),
		Addresses:        []string{generated.Address},
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	restoreMessages := restoreRecorder.messages(t)
	if len(restoreMessages) != 1 || !reflectJSONSubset(restoreMessages[0], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeRestoreBackupResult,
		"id":      "restore-direct",
		"success": true,
	}) {
		t.Fatalf("restore response = %#v", restoreMessages)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(server.keyPaths, auth.DefaultIdentityID, generated.Address)); err != nil {
		t.Fatalf("restored key stat error = %v", err)
	}
	if ir.KeyCount() != 1 {
		t.Fatalf("runtime key count = %d, want 1", ir.KeyCount())
	}
}

func TestIPCRestorePreviewRateLimitsFailures(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.productIdentityRuntime()
	if ir == nil {
		t.Fatal("expected default identity runtime")
	}

	svc := signerAdminServices{signer: server}
	gen := svc.keyApp().GenerateKey(context.Background(), ir, adminproto.GenerateKeyRequest{KeyType: "ed25519"})
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
	// A wrong passphrase fails at the archive's sealed manifest, before any
	// member is inspected: the response carries a top-level failure and
	// says nothing about the archive's contents.
	firstFailure, _ := firstMsgs[0]["error"].(string)
	if firstFailure == "" {
		t.Fatalf("first preview response = %#v, want a decrypt failure", firstMsgs[0])
	}
	if strings.Contains(firstFailure, gen.Address) {
		t.Fatalf("wrong-passphrase preview leaked address %s in %q", gen.Address, firstFailure)
	}
	if keys, present := firstMsgs[0]["keys"].([]any); present && len(keys) > 0 {
		t.Fatalf("wrong-passphrase preview reported archive contents: %#v", keys)
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
		"code": protocol.ResultCodeRestoreRateLimited,
	}) {
		t.Fatalf("second preview response mismatch: %#v", secondMsgs[0])
	}
}
