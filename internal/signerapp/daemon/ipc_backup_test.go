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
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/tokenfile"
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
	if _, err := os.Stat(keys.AccountKeyFilePath(server.keyPaths, auth.DefaultIdentityID, gen.Address)); !os.IsNotExist(err) {
		t.Fatalf("deleted key stat err = %v, want not exist", err)
	}

	server.ipcServer = ipcServer
	activeRecorder := addActiveIdentitySession(t, ipcServer, auth.DefaultIdentityID)

	recoverRecorder := &ipcJSONRecorderConn{}
	recoverSession := newBoundTestSession(ipcServer, recoverRecorder, ir)
	dispatchIPCMessage(t, recoverSession, protocol.RecoverBackupMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRecoverBackup,
			ID:   "recover-backup-test",
		},
		ArchivePath:      filepath.Base(archivePath),
		Addresses:        []string{gen.Address},
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	recoverMsgs := recoverRecorder.messages(t)
	if len(recoverMsgs) != 1 {
		t.Fatalf("recover message count = %d, want 1", len(recoverMsgs))
	}
	if !reflectJSONSubset(recoverMsgs[0], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeRecoverBackupResult,
		"id":      "recover-backup-test",
		"success": true,
	}) {
		t.Fatalf("recover backup response mismatch: %#v", recoverMsgs[0])
	}
	restoreID, _ := recoverMsgs[0]["restore_id"].(string)
	if restoreID == "" {
		t.Fatalf("recover response missing restore_id: %#v", recoverMsgs[0])
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(server.keyPaths, auth.DefaultIdentityID, gen.Address)); !os.IsNotExist(err) {
		t.Fatalf("recovered key became active before review/activation: %v", err)
	}
	if ir.KeyCount() != 0 {
		t.Fatalf("active runtime key count after recovery = %d, want 0", ir.KeyCount())
	}
	if activeMsgs := activeRecorder.messages(t); len(activeMsgs) != 0 {
		t.Fatalf("active notification count after recovery = %d, want 0", len(activeMsgs))
	}

	restartedServer := &Signer{
		registry: identity.NewRegistry(),
		config:   server.config,
		keyPaths: server.keyPaths,
		dataDir:  server.dataDir,
	}
	if _, err := tokenfile.LoadAPlaneToken(server.dataDir, auth.DefaultIdentityID); err != nil {
		t.Fatalf("LoadAPlaneToken(restart) error = %v", err)
	}
	restartedRuntime, err := signerstartup.BuildIdentityRuntime(
		restartedServer.registry,
		testIdentityBuildOptions(restartedServer),
		restartedServer.identityBuildHooks(),
		auth.DefaultIdentityID,
	)
	if err != nil {
		t.Fatalf("BuildIdentityRuntime(restart) error = %v", err)
	}
	success, keyCount, errMsg, code := (signerAdminServices{signer: restartedServer}).
		UnlockIdentity(restartedRuntime, append([]byte(nil), testPassphrase...))
	if !success || keyCount != 0 || errMsg != "" || code != "" {
		t.Fatalf(
			"UnlockIdentity(restart) = success %v keys %d error %q code %q, want inert recovered batch",
			success,
			keyCount,
			errMsg,
			code,
		)
	}
	defer restartedRuntime.Lock()
	if restartedRuntime.KeyCount() != 0 {
		t.Fatalf("restarted runtime key count = %d, want 0", restartedRuntime.KeyCount())
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(server.keyPaths, auth.DefaultIdentityID, gen.Address)); !os.IsNotExist(err) {
		t.Fatalf("recovered key became active after signer restart: %v", err)
	}

	reviewRecorder := &ipcJSONRecorderConn{}
	reviewSession := newBoundTestSession(ipcServer, reviewRecorder, ir)
	dispatchIPCMessage(t, reviewSession, protocol.ReviewRecoveredMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeReviewRecovered,
			ID:   "review-recovered-test",
		},
		RestoreID: restoreID,
	})
	reviewMsgs := reviewRecorder.messages(t)
	if len(reviewMsgs) != 1 {
		t.Fatalf("review message count = %d, want 1", len(reviewMsgs))
	}
	reviewToken, _ := reviewMsgs[0]["review_token"].(string)
	if reviewToken == "" {
		t.Fatalf("review response missing token: %#v", reviewMsgs[0])
	}

	activateRecorder := &ipcJSONRecorderConn{}
	activateSession := newBoundTestSession(ipcServer, activateRecorder, ir)
	dispatchIPCMessage(t, activateSession, protocol.ActivateRecoveredMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeActivateRecovered,
			ID:   "activate-recovered-test",
		},
		RestoreID:   restoreID,
		ReviewToken: reviewToken,
	})
	activateMsgs := activateRecorder.messages(t)
	if len(activateMsgs) != 1 || !reflectJSONSubset(activateMsgs[0], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeActivateRecoveredResult,
		"id":      "activate-recovered-test",
		"success": true,
	}) {
		t.Fatalf("activate response mismatch: %#v", activateMsgs)
	}
	if _, err := os.Stat(keys.AccountKeyFilePath(server.keyPaths, auth.DefaultIdentityID, gen.Address)); err != nil {
		t.Fatalf("activated key stat error = %v", err)
	}
	if ir.KeyCount() != 1 {
		t.Fatalf("active runtime key count after activation = %d, want 1", ir.KeyCount())
	}

	activeMsgs := activeRecorder.messages(t)
	if len(activeMsgs) != 1 {
		t.Fatalf("active notification count = %d, want activation notification", len(activeMsgs))
	}
	if !reflectJSONSubset(activeMsgs[0], map[string]any{
		"kind": string(protocol.MessageKindNotification),
		"type": protocol.MsgTypeKeysChanged,
	}) {
		t.Fatalf("activation notification mismatch: %#v", activeMsgs[0])
	}
}

func TestIPCRecoveredActivationRejectsExistingKeyWithoutReplacement(t *testing.T) {
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

	recoverRecorder := &ipcJSONRecorderConn{}
	recoverSession := newBoundTestSession(ipcServer, recoverRecorder, ir)
	dispatchIPCMessage(t, recoverSession, protocol.RecoverBackupMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRecoverBackup,
			ID:   "recover-existing-test",
		},
		ArchivePath:      filepath.Base(archivePath),
		Addresses:        []string{gen.Address},
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	recoverMsgs := recoverRecorder.messages(t)
	if len(recoverMsgs) != 1 {
		t.Fatalf("recover message count = %d, want 1", len(recoverMsgs))
	}
	restoreID, _ := recoverMsgs[0]["restore_id"].(string)
	if restoreID == "" {
		t.Fatalf("recover response missing restore ID: %#v", recoverMsgs[0])
	}

	reviewRecorder := &ipcJSONRecorderConn{}
	reviewSession := newBoundTestSession(ipcServer, reviewRecorder, ir)
	dispatchIPCMessage(t, reviewSession, protocol.ReviewRecoveredMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeReviewRecovered,
			ID:   "review-existing-test",
		},
		RestoreID: restoreID,
	})
	reviewMsgs := reviewRecorder.messages(t)
	reviewToken, _ := reviewMsgs[0]["review_token"].(string)
	conflicts, _ := reviewMsgs[0]["active_conflicts"].([]any)
	if reviewToken == "" || len(conflicts) != 1 {
		t.Fatalf("review existing response = %#v, want token and conflict", reviewMsgs[0])
	}

	activateRecorder := &ipcJSONRecorderConn{}
	activateSession := newBoundTestSession(ipcServer, activateRecorder, ir)
	dispatchIPCMessage(t, activateSession, protocol.ActivateRecoveredMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeActivateRecovered,
			ID:   "activate-existing-test",
		},
		RestoreID:   restoreID,
		ReviewToken: reviewToken,
	})
	activateMsgs := activateRecorder.messages(t)
	if len(activateMsgs) != 1 ||
		activateMsgs[0]["code"] != protocol.ResultCodeActivationConflict ||
		activateMsgs[0]["success"] != false {
		t.Fatalf("activate existing response = %#v, want conflict", activateMsgs)
	}
	if activeMsgs := activeRecorder.messages(t); len(activeMsgs) != 0 {
		t.Fatalf("active notification count = %d, want 0 for rejected activation: %#v", len(activeMsgs), activeMsgs)
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
		"code": protocol.ResultCodeRestoreRateLimited,
	}) {
		t.Fatalf("second preview response mismatch: %#v", secondMsgs[0])
	}
}
