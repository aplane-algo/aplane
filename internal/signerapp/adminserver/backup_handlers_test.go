// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"encoding/json"
	"github.com/aplane-algo/aplane/internal/adminproto"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

func TestBackupRestoreMessagesDispatchToBackupServices(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()

	svc := &stubServices{
		backupResult: adminproto.BackupIdentityResult{
			Success:     true,
			ArchivePath: "/data/identities/default/backups/backup.tar.gz",
		},
		listBackupsResult: adminproto.ListBackupsResult{
			Backups: []adminproto.BackupInfo{{
				Path:      "/data/identities/default/backups/backup.tar.gz",
				FileName:  "backup.tar.gz",
				CreatedAt: 1710000000,
				Size:      4096,
				Checksum:  "abc123",
				Verified:  true,
			}},
		},
		deleteBackupResult: adminproto.DeleteBackupResult{Success: true},
		previewRestoreResult: adminproto.RestorePreviewResult{
			ArchivePath: "/data/identities/default/backups/backup.tar.gz",
			Keys: []adminproto.RestoreKeyInfo{{
				Address:       "ADDR1",
				KeyType:       "ed25519",
				AlreadyExists: true,
			}},
		},
		restoreBackupResult: adminproto.RestoreBackupResult{
			ArchivePath: "/data/identities/default/backups/backup.tar.gz",
			Success:     true,
			Restored: []adminproto.RestoreKeyInfo{{
				Address: "ADDR1",
				KeyType: "ed25519",
			}},
			Warnings: []adminproto.RestoreWarning{{
				Address: "ADDR1",
				KeyType: "aplane.timed-whitelist.v1",
				Warning: "skipped bundled template for aplane.timed-whitelist.v1: backup template conflicts with existing keystore definition",
			}},
			KeyCount: 1,
		},
	}
	conn := &queueConn{}
	session := NewSession(conn, svc.backupDeps())
	session.Bind(auth.NewDefaultIdentity("test"), ir)

	dispatchAdminMessage(t, session, protocol.BackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeBackup, ID: "backup-1"},
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	dispatchAdminMessage(t, session, protocol.ListBackupsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListBackups, ID: "list-backups-1"},
	})
	dispatchAdminMessage(t, session, protocol.DeleteBackupMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDeleteBackup, ID: "delete-backup-1"},
		ArchivePath: "backup.tar.gz",
	})
	dispatchAdminMessage(t, session, protocol.PreviewRestoreMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypePreviewRestore, ID: "preview-1"},
		ArchivePath:      "backup.tar.gz",
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	dispatchAdminMessage(t, session, protocol.RestoreBackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackup, ID: "restore-1"},
		ArchivePath:      "backup.tar.gz",
		Addresses:        []string{"ADDR1"},
		Overwrite:        true,
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})

	if svc.backupCalls != 1 {
		t.Fatalf("BackupIdentity calls = %d, want 1", svc.backupCalls)
	}
	if string(svc.lastBackupRequest.ExportPassphrase) != "export-passphrase" {
		t.Fatalf("backup request = %+v, want export passphrase", svc.lastBackupRequest)
	}
	if svc.listBackupsCalls != 1 {
		t.Fatalf("ListBackups calls = %d, want 1", svc.listBackupsCalls)
	}
	if svc.deleteBackupCalls != 1 {
		t.Fatalf("DeleteBackup calls = %d, want 1", svc.deleteBackupCalls)
	}
	if svc.lastDeleteBackup.ArchivePath != "backup.tar.gz" {
		t.Fatalf("delete request = %+v, want backup.tar.gz", svc.lastDeleteBackup)
	}
	if svc.previewRestoreCalls != 1 {
		t.Fatalf("PreviewRestore calls = %d, want 1", svc.previewRestoreCalls)
	}
	if svc.lastPreviewRestore.ArchivePath != "backup.tar.gz" || string(svc.lastPreviewRestore.ExportPassphrase) != "export-passphrase" {
		t.Fatalf("preview request = %+v, want archive and passphrase", svc.lastPreviewRestore)
	}
	if svc.restoreBackupCalls != 1 {
		t.Fatalf("RestoreBackup calls = %d, want 1", svc.restoreBackupCalls)
	}
	if svc.lastRestoreBackup.ArchivePath != "backup.tar.gz" || !svc.lastRestoreBackup.Overwrite {
		t.Fatalf("restore request = %+v, want archive and overwrite", svc.lastRestoreBackup)
	}
	if len(svc.lastRestoreBackup.Addresses) != 1 || svc.lastRestoreBackup.Addresses[0] != "ADDR1" {
		t.Fatalf("restore addresses = %v, want [ADDR1]", svc.lastRestoreBackup.Addresses)
	}

	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 5 {
		t.Fatalf("write count = %d, want 5", len(msgs))
	}
	assertAdminProtoMessage(t, msgs[0], protocol.MsgTypeBackupResult, "backup-1")
	assertAdminProtoMessage(t, msgs[1], protocol.MsgTypeBackupsList, "list-backups-1")
	assertAdminProtoMessage(t, msgs[2], protocol.MsgTypeDeleteBackupResult, "delete-backup-1")
	assertAdminProtoMessage(t, msgs[3], protocol.MsgTypeRestorePreview, "preview-1")
	assertAdminProtoMessage(t, msgs[4], protocol.MsgTypeRestoreBackupResult, "restore-1")

	var restoreResult protocol.RestoreBackupResultMessage
	if err := json.Unmarshal(conn.writes[4], &restoreResult); err != nil {
		t.Fatalf("decode restore result: %v", err)
	}
	if !restoreResult.Success || restoreResult.KeyCount != 1 {
		t.Fatalf("restore result = %+v, want success with key_count 1", restoreResult)
	}
	if len(restoreResult.Warnings) != 1 || restoreResult.Warnings[0].KeyType != "aplane.timed-whitelist.v1" {
		t.Fatalf("restore warnings = %+v, want aplane.timed-whitelist.v1 warning", restoreResult.Warnings)
	}
}

func TestRestoreBackupRequiresUnlockedRuntime(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})

	svc := &stubServices{}
	conn := &queueConn{}
	session := NewSession(conn, svc.backupDeps())
	session.Bind(auth.NewDefaultIdentity("test"), ir)

	dispatchAdminMessage(t, session, protocol.RestoreBackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackup, ID: "restore-locked"},
		ArchivePath:      "backup.tar.gz",
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})

	if svc.restoreBackupCalls != 0 {
		t.Fatalf("RestoreBackup calls = %d, want 0 while locked", svc.restoreBackupCalls)
	}
	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 {
		t.Fatalf("write count = %d, want 1", len(msgs))
	}
	if msgs[0].Type != protocol.MsgTypeError || msgs[0].Code != protocol.ErrCodeSignerLocked {
		t.Fatalf("locked response = %+v, want signer_locked error", msgs[0])
	}
}

func TestBackupRestoreMessagesRequireIdentityRestoreAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name          string
		dispatch      func(*Session)
		wantRequestID string
		wantCalls     func(*stubServices) int
	}{
		{
			name: "list backups",
			dispatch: func(session *Session) {
				session.HandleListBackups("list-authz")
			},
			wantRequestID: "list-authz",
			wantCalls:     func(s *stubServices) int { return s.listBackupsCalls },
		},
		{
			name: "preview restore",
			dispatch: func(session *Session) {
				session.HandlePreviewRestore(&protocol.PreviewRestoreMessage{
					BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypePreviewRestore, ID: "preview-authz"},
					ArchivePath:      "backup.tar.gz",
					ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
				})
			},
			wantRequestID: "preview-authz",
			wantCalls:     func(s *stubServices) int { return s.previewRestoreCalls },
		},
		{
			name: "restore backup",
			dispatch: func(session *Session) {
				session.HandleRestoreBackup(&protocol.RestoreBackupMessage{
					BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackup, ID: "restore-authz"},
					ArchivePath:      "backup.tar.gz",
					ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
				})
			},
			wantRequestID: "restore-authz",
			wantCalls:     func(s *stubServices) int { return s.restoreBackupCalls },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ir := identity.New(identity.Config{
				ID:            auth.DefaultIdentityID,
				Authenticator: auth.NewTokenAuthenticator("token"),
			})
			ir.SetUnlocked()

			svc := &stubServices{}
			authorizer := &recordingAuthorizer{err: auth.ErrForbidden}
			conn := &queueConn{}
			session := NewSession(conn, SessionDeps{
				Backups:    svc,
				Authorizer: authorizer,
			})
			session.Bind(&auth.Identity{ID: "admin-principal", Type: "human", Method: "test"}, ir)

			tc.dispatch(session)

			if calls := tc.wantCalls(svc); calls != 0 {
				t.Fatalf("service calls = %d, want 0 after authorization denial", calls)
			}
			if authorizer.got.action != auth.ActionIdentityRestore {
				t.Fatalf("authorizer action = %q, want %q", authorizer.got.action, auth.ActionIdentityRestore)
			}
			if authorizer.got.resource.Type != "identity" || authorizer.got.resource.ID != auth.DefaultIdentityID || authorizer.got.resource.IdentityID != auth.DefaultIdentityID {
				t.Fatalf("authorizer resource = %+v, want identity/default", authorizer.got.resource)
			}

			msgs := decodeAdminProtoWrites(t, conn)
			if len(msgs) != 1 {
				t.Fatalf("write count = %d, want 1", len(msgs))
			}
			if msgs[0].Type != protocol.MsgTypeError || msgs[0].ID != tc.wantRequestID || msgs[0].Code != protocol.ErrCodeAuthorizationDenied {
				t.Fatalf("response = %+v, want authorization_denied error for %s", msgs[0], tc.wantRequestID)
			}
		})
	}
}

func TestRestoreHandlersZeroProtocolPassphrases(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()

	svc := &stubServices{
		previewRestoreResult: adminproto.RestorePreviewResult{ArchivePath: "backup.tar.gz"},
		restoreBackupResult:  adminproto.RestoreBackupResult{ArchivePath: "backup.tar.gz", Success: true},
	}
	conn := &queueConn{}
	session := NewSession(conn, svc.backupDeps())
	session.Bind(auth.NewDefaultIdentity("test"), ir)

	previewMsg := &protocol.PreviewRestoreMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypePreviewRestore, ID: "preview-zero"},
		ArchivePath:      "backup.tar.gz",
		ExportPassphrase: protocol.NewSensitiveBytes("preview-passphrase"),
	}
	session.HandlePreviewRestore(previewMsg)
	if string(svc.lastPreviewRestore.ExportPassphrase) != "preview-passphrase" {
		t.Fatalf("service preview passphrase = %q, want original passphrase", string(svc.lastPreviewRestore.ExportPassphrase))
	}
	assertSensitiveBytesZeroed(t, previewMsg.ExportPassphrase)

	restoreMsg := &protocol.RestoreBackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackup, ID: "restore-zero"},
		ArchivePath:      "backup.tar.gz",
		ExportPassphrase: protocol.NewSensitiveBytes("restore-passphrase"),
	}
	session.HandleRestoreBackup(restoreMsg)
	if string(svc.lastRestoreBackup.ExportPassphrase) != "restore-passphrase" {
		t.Fatalf("service restore passphrase = %q, want original passphrase", string(svc.lastRestoreBackup.ExportPassphrase))
	}
	assertSensitiveBytesZeroed(t, restoreMsg.ExportPassphrase)
}

func TestBackupHandlerZeroesProtocolPassphrase(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()

	svc := &stubServices{
		backupResult: adminproto.BackupIdentityResult{ArchivePath: "backup.tar.gz", Success: true},
	}
	conn := &queueConn{}
	session := NewSession(conn, svc.backupDeps())
	session.Bind(auth.NewDefaultIdentity("test"), ir)

	msg := &protocol.BackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeBackup, ID: "backup-zero"},
		ExportPassphrase: protocol.NewSensitiveBytes("backup-passphrase"),
	}
	session.HandleBackup(msg)
	if string(svc.lastBackupRequest.ExportPassphrase) != "backup-passphrase" {
		t.Fatalf("service backup passphrase = %q, want original passphrase", string(svc.lastBackupRequest.ExportPassphrase))
	}
	assertSensitiveBytesZeroed(t, msg.ExportPassphrase)
}

func TestRestoreHandlersWriteAuditEvents(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()

	svc := &stubServices{
		previewRestoreResult: adminproto.RestorePreviewResult{
			ArchivePath: "backup.tar.gz",
			Keys:        []adminproto.RestoreKeyInfo{{Address: "ADDR1", KeyType: "ed25519"}},
		},
		restoreBackupResult: adminproto.RestoreBackupResult{
			ArchivePath: "backup.tar.gz",
			Success:     true,
			Restored:    []adminproto.RestoreKeyInfo{{Address: "ADDR1", KeyType: "ed25519"}},
		},
	}
	audit := &recordingRestoreAudit{}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{
		Backups: svc,
		Audit:   audit,
	})
	session.Bind(auth.NewDefaultIdentity("test"), ir)

	session.HandlePreviewRestore(&protocol.PreviewRestoreMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypePreviewRestore, ID: "preview-audit"},
		ArchivePath:      "backup.tar.gz",
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	session.HandleRestoreBackup(&protocol.RestoreBackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackup, ID: "restore-audit"},
		ArchivePath:      "backup.tar.gz",
		Addresses:        []string{"ADDR1"},
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})

	if audit.previewedArchive != "backup.tar.gz" || audit.previewedCount != 1 {
		t.Fatalf("preview audit = archive %q count %d, want backup.tar.gz/1", audit.previewedArchive, audit.previewedCount)
	}
	if audit.startedArchive != "backup.tar.gz" || audit.startedCount != 1 {
		t.Fatalf("started audit = archive %q count %d, want backup.tar.gz/1", audit.startedArchive, audit.startedCount)
	}
	if audit.completedArchive != "backup.tar.gz" || audit.completedCount != 1 {
		t.Fatalf("completed audit = archive %q count %d, want backup.tar.gz/1", audit.completedArchive, audit.completedCount)
	}
}

type recordingRestoreAudit struct {
	recordingAuthorizationAudit

	previewedArchive string
	previewedCount   int
	failedReason     string
	startedArchive   string
	startedCount     int
	completedArchive string
	completedCount   int
	partialArchive   string
	partialRestored  int
	partialFailed    int
}

func (a *recordingRestoreAudit) LogBackupRestorePreviewedContext(ctx SessionContext, archivePath string, keyCount int) {
	_ = ctx
	a.previewedArchive = archivePath
	a.previewedCount = keyCount
}

func (a *recordingRestoreAudit) LogBackupRestorePreviewFailedContext(ctx SessionContext, reason string) {
	_ = ctx
	a.failedReason = reason
}

func (a *recordingRestoreAudit) LogBackupRestoreStartedContext(ctx SessionContext, archivePath string, selectedCount int) {
	_ = ctx
	a.startedArchive = archivePath
	a.startedCount = selectedCount
}

func (a *recordingRestoreAudit) LogBackupRestoreCompletedContext(ctx SessionContext, archivePath string, restoredCount int) {
	_ = ctx
	a.completedArchive = archivePath
	a.completedCount = restoredCount
}

func (a *recordingRestoreAudit) LogBackupRestorePartialContext(ctx SessionContext, archivePath string, restoredCount, failedCount int) {
	_ = ctx
	a.partialArchive = archivePath
	a.partialRestored = restoredCount
	a.partialFailed = failedCount
}

func (a *recordingRestoreAudit) LogBackupRestoreFailedContext(ctx SessionContext, reason string) {
	_ = ctx
	a.failedReason = reason
}

func assertSensitiveBytesZeroed(t *testing.T, data protocol.SensitiveBytes) {
	t.Helper()
	if len(data) == 0 {
		t.Fatal("sensitive bytes length = 0, want same mutable buffer zeroed")
	}
	for i, b := range data {
		if b != 0 {
			t.Fatalf("sensitive byte %d = %d, want zero", i, b)
		}
	}
}
