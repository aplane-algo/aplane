// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

func TestBackupRestoreMessagesDispatchToBackupServices(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	svc := &stubServices{
		backupResult:         adminproto.BackupIdentityResult{Success: true},
		listBackupsResult:    adminproto.ListBackupsResult{},
		deleteBackupResult:   adminproto.DeleteBackupResult{Success: true},
		previewRestoreResult: adminproto.RestorePreviewResult{},
	}
	conn := &queueConn{}
	session := NewSession(conn, svc.backupDeps())
	session.Bind(auth.NewProductIdentity("test"), ir)
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
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	svc := &stubServices{restoreBackupResult: adminproto.RestoreBackupResult{Success: true}}
	audit := &recordingCredentialRestoreAudit{}
	deps := svc.backupDeps()
	deps.Audit = audit
	conn := &queueConn{}
	session := NewSession(conn, deps)
	session.Bind(auth.NewProductIdentity("test"), ir)
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
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	svc := &stubServices{}
	audit := &recordingCredentialRestoreAudit{intentErr: errors.New("sync failed")}
	deps := svc.backupDeps()
	deps.Audit = audit
	conn := &queueConn{}
	session := NewSession(conn, deps)
	session.Bind(auth.NewProductIdentity("test"), ir)
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
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetRecovery()
	svc := &stubServices{}
	audit := &recordingCredentialRestoreAudit{}
	deps := svc.backupDeps()
	deps.Audit = audit
	session := NewSession(&queueConn{}, deps)
	session.Bind(auth.NewProductIdentity("test"), ir)
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

func TestCommitBackupImportClonesAndZerosWirePassphrase(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	svc := &stubServices{}
	session := NewSession(&queueConn{}, svc.backupDeps())
	session.Bind(auth.NewProductIdentity("test"), ir)
	msg := &protocol.CommitBackupImportMessage{
		BaseMessage: protocol.BaseMessage{ID: "import-commit"},
		UploadID:    ".import-repair.part", FileName: "repair.tar.gz",
		ExpectedSize: 1, ExpectedSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	}
	session.HandleCommitBackupImport(msg)
	if got := string(svc.lastCommitBackupImport.ExportPassphrase); got != "export-passphrase" {
		t.Fatalf("service export passphrase = %q", got)
	}
	if got := string(msg.ExportPassphrase); got == "export-passphrase" {
		t.Fatal("wire export passphrase was not zeroed")
	}
}

func TestBackupTransferAuditsImportFailureAndExportStart(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	svc := &stubServices{
		commitBackupImportResult: adminproto.CommitBackupImportResult{Code: "backup_import_commit_failed", Error: "invalid archive"},
		readBackupChunkResult:    adminproto.ReadBackupChunkResult{Success: true, FileName: "export.tar.gz", Offset: 1, Data: []byte("chunk")},
	}
	audit := &recordingBackupTransferAudit{}
	deps := svc.backupDeps()
	deps.Audit = audit
	session := NewSession(&queueConn{}, deps)
	session.Bind(auth.NewProductIdentity("test"), ir)

	session.HandleCommitBackupImport(&protocol.CommitBackupImportMessage{
		BaseMessage: protocol.BaseMessage{ID: "commit"}, FileName: "import.tar.gz",
		ExportPassphrase: protocol.NewSensitiveBytes("passphrase"),
	})
	session.HandleReadBackupChunk(&protocol.ReadBackupChunkMessage{
		BaseMessage: protocol.BaseMessage{ID: "read"}, FileName: "export.tar.gz", Offset: 1,
	})
	session.HandleReadBackupChunk(&protocol.ReadBackupChunkMessage{
		BaseMessage: protocol.BaseMessage{ID: "read-continuation"}, FileName: "export.tar.gz", Offset: 2,
	})

	if audit.failedCalls != 1 || !strings.Contains(audit.lastFailure, "backup import failed") {
		t.Fatalf("failure audit = %d %q", audit.failedCalls, audit.lastFailure)
	}
	if audit.exportStartedCalls != 1 || audit.lastExport != "export.tar.gz" {
		t.Fatalf("export audit = %d %q", audit.exportStartedCalls, audit.lastExport)
	}
}

func TestBackupExportAuditStartsAgainAfterEOF(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	svc := &stubServices{
		readBackupChunkResult: adminproto.ReadBackupChunkResult{Success: true, FileName: "export.tar.gz", Offset: 7, EOF: true},
	}
	audit := &recordingBackupTransferAudit{}
	deps := svc.backupDeps()
	deps.Audit = audit
	session := NewSession(&queueConn{}, deps)
	session.Bind(auth.NewProductIdentity("test"), ir)

	session.HandleReadBackupChunk(&protocol.ReadBackupChunkMessage{
		BaseMessage: protocol.BaseMessage{ID: "read-to-eof"}, FileName: "export.tar.gz", Offset: 7,
	})
	svc.readBackupChunkResult.EOF = false
	session.HandleReadBackupChunk(&protocol.ReadBackupChunkMessage{
		BaseMessage: protocol.BaseMessage{ID: "read-again"}, FileName: "export.tar.gz", Offset: 7,
	})

	if audit.exportStartedCalls != 2 {
		t.Fatalf("export audit calls = %d, want 2 transfers", audit.exportStartedCalls)
	}
}

func TestBackupTransferSuccessAuditsDoNotRequireFailureCapability(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	svc := &stubServices{
		commitBackupImportResult: adminproto.CommitBackupImportResult{
			Success: true,
			Backup:  adminproto.BackupInfo{FileName: "import.tar.gz", Size: 42},
		},
		readBackupChunkResult: adminproto.ReadBackupChunkResult{
			Success: true, FileName: "export.tar.gz", Data: []byte("chunk"),
		},
	}
	audit := &backupSuccessOnlyAudit{}
	deps := svc.backupDeps()
	deps.Audit = audit
	session := NewSession(&queueConn{}, deps)
	session.Bind(auth.NewProductIdentity("test"), ir)

	session.HandleCommitBackupImport(&protocol.CommitBackupImportMessage{
		BaseMessage: protocol.BaseMessage{ID: "commit"}, FileName: "import.tar.gz",
		ExportPassphrase: protocol.NewSensitiveBytes("passphrase"),
	})
	session.HandleReadBackupChunk(&protocol.ReadBackupChunkMessage{
		BaseMessage: protocol.BaseMessage{ID: "read"}, FileName: "export.tar.gz",
	})

	if audit.importedCalls != 1 || audit.exportStartedCalls != 1 {
		t.Fatalf("success audit calls = import %d export %d, want 1/1", audit.importedCalls, audit.exportStartedCalls)
	}
}

func TestBackupTransferFailureAuditDoesNotRequireSuccessCapabilities(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	svc := &stubServices{
		commitBackupImportResult: adminproto.CommitBackupImportResult{Error: "invalid archive"},
		readBackupChunkResult:    adminproto.ReadBackupChunkResult{Error: "read failed"},
	}
	audit := &backupFailureOnlyAudit{}
	deps := svc.backupDeps()
	deps.Audit = audit
	session := NewSession(&queueConn{}, deps)
	session.Bind(auth.NewProductIdentity("test"), ir)

	session.HandleCommitBackupImport(&protocol.CommitBackupImportMessage{
		BaseMessage: protocol.BaseMessage{ID: "commit"}, FileName: "import.tar.gz",
		ExportPassphrase: protocol.NewSensitiveBytes("passphrase"),
	})
	session.HandleReadBackupChunk(&protocol.ReadBackupChunkMessage{
		BaseMessage: protocol.BaseMessage{ID: "read"}, FileName: "export.tar.gz",
	})

	if audit.failedCalls != 2 {
		t.Fatalf("failure audit calls = %d, want 2", audit.failedCalls)
	}
}

func TestLockedStateRejectsRecoveryCapableRestoreReads(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	svc := &stubServices{}
	conn := &queueConn{}
	session := NewSession(conn, svc.backupDeps())
	session.Bind(auth.NewProductIdentity("test"), ir)
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

func TestBackupTransferHandlersRejectUnavailableService(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	ir.SetUnlocked()
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{})
	session.Bind(auth.NewProductIdentity("test"), ir)

	session.HandleBeginBackupImport(&protocol.BeginBackupImportMessage{BaseMessage: protocol.BaseMessage{ID: "begin"}, FileName: "backup.tar.gz"})
	session.HandleAppendBackupImport(&protocol.AppendBackupImportMessage{BaseMessage: protocol.BaseMessage{ID: "append"}, UploadID: ".import-test.part", Data: []byte("x")})
	session.HandleCommitBackupImport(&protocol.CommitBackupImportMessage{BaseMessage: protocol.BaseMessage{ID: "commit"}, UploadID: ".import-test.part", FileName: "backup.tar.gz"})
	session.HandleAbortBackupImport(&protocol.AbortBackupImportMessage{BaseMessage: protocol.BaseMessage{ID: "abort"}, UploadID: ".import-test.part"})
	session.HandleReadBackupChunk(&protocol.ReadBackupChunkMessage{BaseMessage: protocol.BaseMessage{ID: "read"}, FileName: "backup.tar.gz"})

	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 5 {
		t.Fatalf("response count = %d, want 5", len(msgs))
	}
	for _, msg := range msgs {
		if msg.Type != protocol.MsgTypeError {
			t.Fatalf("unavailable backup service response = %+v, want error", msg)
		}
	}
}

func TestLockedStatePermitsAbortingUnpublishedBackupUpload(t *testing.T) {
	ir := productruntime.New(productruntime.Config{Authenticator: auth.NewTokenAuthenticator("token")})
	svc := &stubServices{}
	conn := &queueConn{}
	session := NewSession(conn, svc.backupDeps())
	session.Bind(auth.NewProductIdentity("test"), ir)
	session.HandleAbortBackupImport(&protocol.AbortBackupImportMessage{
		BaseMessage: protocol.BaseMessage{ID: "abort-locked"}, UploadID: ".import-test.part",
	})

	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 || msgs[0].Type != protocol.MsgTypeAbortBackupImportResult {
		t.Fatalf("locked abort response = %+v, want abort result", msgs)
	}
}

type recordingCredentialRestoreAudit struct {
	recordingAuthorizationAudit
	intentCalls int
	intentErr   error
}

type recordingBackupTransferAudit struct {
	recordingAuthorizationAudit
	failedCalls        int
	exportStartedCalls int
	lastFailure        string
	lastExport         string
}

type backupSuccessOnlyAudit struct {
	recordingAuthorizationAudit
	importedCalls      int
	exportStartedCalls int
}

func (a *backupSuccessOnlyAudit) LogBackupImportedContext(SessionContext, string, int64) {
	a.importedCalls++
}

func (a *backupSuccessOnlyAudit) LogBackupExportStartedContext(SessionContext, string) {
	a.exportStartedCalls++
}

type backupFailureOnlyAudit struct {
	recordingAuthorizationAudit
	failedCalls int
}

func (a *backupFailureOnlyAudit) LogBackupFailedContext(SessionContext, string) {
	a.failedCalls++
}

func (*recordingBackupTransferAudit) LogBackupImportedContext(SessionContext, string, int64) {}

func (a *recordingBackupTransferAudit) LogBackupFailedContext(_ SessionContext, reason string) {
	a.failedCalls++
	a.lastFailure = reason
}

func (a *recordingBackupTransferAudit) LogBackupExportStartedContext(_ SessionContext, fileName string) {
	a.exportStartedCalls++
	a.lastExport = fileName
}

func (a *recordingCredentialRestoreAudit) LogCredentialRestoreIntentDurableContext(SessionContext, string, string, bool) error {
	a.intentCalls++
	return a.intentErr
}

func (a *recordingCredentialRestoreAudit) LogCredentialRestoreContext(SessionContext, adminproto.RestoreBackupResult) {
}
func (a *recordingCredentialRestoreAudit) LogCredentialRestoreRollbackContext(SessionContext, adminproto.RollbackRestoreResult) {
}
