// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

func TestBackupRestoreMessagesDispatchToBackupServices(t *testing.T) {
	ir := identity.New(identity.Config{ID: auth.DefaultIdentityID, Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	svc := &stubServices{
		backupResult:         adminproto.BackupIdentityResult{Success: true},
		listBackupsResult:    adminproto.ListBackupsResult{},
		deleteBackupResult:   adminproto.DeleteBackupResult{Success: true},
		previewRestoreResult: adminproto.RestorePreviewResult{},
	}
	conn := &queueConn{}
	session := NewSession(conn, svc.backupDeps())
	session.Bind(auth.NewDefaultIdentity("test"), ir)
	dispatchAdminMessage(t, session, protocol.BackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeBackup, ID: "backup-1"},
		ExportPassphrase: protocol.NewSensitiveBytes("passphrase"),
	})
	dispatchAdminMessage(t, session, protocol.ListBackupsMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListBackups, ID: "list-1"}})
	dispatchAdminMessage(t, session, protocol.DeleteBackupMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDeleteBackup, ID: "delete-1"}, ArchivePath: "backup.tar.gz",
	})
	dispatchAdminMessage(t, session, protocol.PreviewRestoreMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePreviewRestore, ID: "preview-1"},
		ArchivePath: "backup.tar.gz", ExportPassphrase: protocol.NewSensitiveBytes("passphrase"),
	})
	if svc.backupCalls != 1 || svc.listBackupsCalls != 1 || svc.deleteBackupCalls != 1 || svc.previewRestoreCalls != 1 {
		t.Fatalf("service calls = backup %d list %d delete %d preview %d", svc.backupCalls, svc.listBackupsCalls, svc.deleteBackupCalls, svc.previewRestoreCalls)
	}
}

func TestRestoreBackupRequiresDurableIntentBeforeService(t *testing.T) {
	ir := identity.New(identity.Config{ID: auth.DefaultIdentityID, Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	svc := &stubServices{restoreBackupResult: adminproto.RestoreBackupResult{Success: true}}
	audit := &recordingCredentialRestoreAudit{}
	deps := svc.backupDeps()
	deps.Audit = audit
	conn := &queueConn{}
	session := NewSession(conn, deps)
	session.Bind(auth.NewDefaultIdentity("test"), ir)
	msg := protocol.RestoreBackupMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackup, ID: "restore-1"},
		ArchivePath: "backup.tar.gz", ExportPassphrase: protocol.NewSensitiveBytes("passphrase"), ReplaceExisting: true,
	}
	dispatchAdminMessage(t, session, msg)
	if audit.intentCalls != 1 || svc.restoreBackupCalls != 1 {
		t.Fatalf("intent calls = %d, service calls = %d", audit.intentCalls, svc.restoreBackupCalls)
	}
	if svc.lastRestoreBackup.OperationID != "restore-1" || !svc.lastRestoreBackup.ReplaceExisting {
		t.Fatalf("restore request = %+v", svc.lastRestoreBackup)
	}
}

func TestRestoreBackupAbortsWhenDurableIntentFails(t *testing.T) {
	ir := identity.New(identity.Config{ID: auth.DefaultIdentityID, Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	svc := &stubServices{}
	audit := &recordingCredentialRestoreAudit{intentErr: errors.New("sync failed")}
	deps := svc.backupDeps()
	deps.Audit = audit
	conn := &queueConn{}
	session := NewSession(conn, deps)
	session.Bind(auth.NewDefaultIdentity("test"), ir)
	dispatchAdminMessage(t, session, protocol.RestoreBackupMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackup, ID: "restore-fail"},
		ArchivePath: "backup.tar.gz", ExportPassphrase: protocol.NewSensitiveBytes("passphrase"),
	})
	if svc.restoreBackupCalls != 0 {
		t.Fatalf("restore service called %d times after audit failure", svc.restoreBackupCalls)
	}
	var result protocol.RestoreBackupResultMessage
	if err := json.Unmarshal(conn.writes[0], &result); err != nil {
		t.Fatal(err)
	}
	if result.Code != protocol.ResultCodeRestoreAuditFailed {
		t.Fatalf("result = %+v", result)
	}
}

func TestRecoveryStatePermitsRestoreReadApplyRollbackAndReconcile(t *testing.T) {
	ir := identity.New(identity.Config{ID: auth.DefaultIdentityID, Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetRecovery()
	svc := &stubServices{}
	audit := &recordingCredentialRestoreAudit{}
	deps := svc.backupDeps()
	deps.Audit = audit
	session := NewSession(&queueConn{}, deps)
	session.Bind(auth.NewDefaultIdentity("test"), ir)
	session.HandleListBackups("list")
	session.HandleBeginBackupImport(&protocol.BeginBackupImportMessage{
		BaseMessage: protocol.BaseMessage{ID: "import-begin"}, FileName: "repair.tar.gz",
	})
	session.HandleAppendBackupImport(&protocol.AppendBackupImportMessage{
		BaseMessage: protocol.BaseMessage{ID: "import-append"}, UploadID: ".import-repair.part", Data: []byte("archive"),
	})
	session.HandleCommitBackupImport(&protocol.CommitBackupImportMessage{
		BaseMessage: protocol.BaseMessage{ID: "import-commit"}, UploadID: ".import-repair.part", FileName: "repair.tar.gz",
	})
	session.HandleReadBackupChunk(&protocol.ReadBackupChunkMessage{
		BaseMessage: protocol.BaseMessage{ID: "read"}, FileName: "repair.tar.gz",
	})
	session.HandlePreviewRestore(&protocol.PreviewRestoreMessage{
		BaseMessage: protocol.BaseMessage{ID: "preview"}, ExportPassphrase: protocol.NewSensitiveBytes("passphrase"),
	})
	session.HandleRestoreBackup(&protocol.RestoreBackupMessage{
		BaseMessage: protocol.BaseMessage{ID: "restore"}, ExportPassphrase: protocol.NewSensitiveBytes("passphrase"),
	})
	session.HandleRollbackRestore(&protocol.RollbackRestoreMessage{BaseMessage: protocol.BaseMessage{ID: "rollback"}})
	session.HandleReconcileStore("reconcile")
	if svc.listBackupsCalls != 1 || svc.beginBackupImportCalls != 1 || svc.appendBackupImportCalls != 1 || svc.commitBackupImportCalls != 1 || svc.readBackupChunkCalls != 1 || svc.previewRestoreCalls != 1 || svc.restoreBackupCalls != 1 || svc.rollbackRestoreCalls != 1 || svc.reconcileStoreCalls != 1 {
		t.Fatalf("recovery calls = list %d import %d/%d/%d read %d preview %d restore %d rollback %d reconcile %d",
			svc.listBackupsCalls, svc.beginBackupImportCalls, svc.appendBackupImportCalls, svc.commitBackupImportCalls,
			svc.readBackupChunkCalls, svc.previewRestoreCalls, svc.restoreBackupCalls, svc.rollbackRestoreCalls, svc.reconcileStoreCalls)
	}
}

func TestLockedStateRejectsRecoveryCapableRestoreReads(t *testing.T) {
	ir := identity.New(identity.Config{ID: auth.DefaultIdentityID, Authenticator: auth.NewTokenAuthenticator("token")})
	svc := &stubServices{}
	conn := &queueConn{}
	session := NewSession(conn, svc.backupDeps())
	session.Bind(auth.NewDefaultIdentity("test"), ir)
	session.HandleListBackups("list-locked")
	session.HandleBeginBackupImport(&protocol.BeginBackupImportMessage{
		BaseMessage: protocol.BaseMessage{ID: "import-locked"}, FileName: "repair.tar.gz",
	})
	session.HandleReadBackupChunk(&protocol.ReadBackupChunkMessage{
		BaseMessage: protocol.BaseMessage{ID: "read-locked"}, FileName: "repair.tar.gz",
	})
	session.HandlePreviewRestore(&protocol.PreviewRestoreMessage{
		BaseMessage:      protocol.BaseMessage{ID: "preview-locked"},
		ExportPassphrase: protocol.NewSensitiveBytes("passphrase"),
	})
	if svc.listBackupsCalls != 0 || svc.beginBackupImportCalls != 0 || svc.readBackupChunkCalls != 0 || svc.previewRestoreCalls != 0 {
		t.Fatalf("locked service calls = list %d import %d read %d preview %d", svc.listBackupsCalls, svc.beginBackupImportCalls, svc.readBackupChunkCalls, svc.previewRestoreCalls)
	}
	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 4 {
		t.Fatalf("locked response count = %d, want 4", len(msgs))
	}
	for _, msg := range msgs {
		if msg.Type != protocol.MsgTypeError || msg.Code != protocol.ErrCodeSignerLocked {
			t.Fatalf("locked response = %+v, want signer_locked error", msg)
		}
	}
}

type recordingCredentialRestoreAudit struct {
	recordingAuthorizationAudit
	intentCalls int
	intentErr   error
}

func (a *recordingCredentialRestoreAudit) LogCredentialRestoreIntentDurableContext(SessionContext, string, string, bool) error {
	a.intentCalls++
	return a.intentErr
}

func (a *recordingCredentialRestoreAudit) LogCredentialRestoreContext(SessionContext, adminproto.RestoreBackupResult) {
}
func (a *recordingCredentialRestoreAudit) LogCredentialRestoreRollbackContext(SessionContext, adminproto.RollbackRestoreResult) {
}
