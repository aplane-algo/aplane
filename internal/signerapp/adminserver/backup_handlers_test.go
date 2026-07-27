// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
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
	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 4 {
		t.Fatalf("write count = %d, want 4", len(msgs))
	}
	assertAdminProtoMessage(t, msgs[0], protocol.MsgTypeBackupResult, "backup-1")
	assertAdminProtoMessage(t, msgs[1], protocol.MsgTypeBackupsList, "list-backups-1")
	assertAdminProtoMessage(t, msgs[2], protocol.MsgTypeDeleteBackupResult, "delete-backup-1")
	assertAdminProtoMessage(t, msgs[3], protocol.MsgTypeRestorePreview, "preview-1")
}

func TestLegacyRestoreBackupIsNotDispatched(t *testing.T) {
	conn := &queueConn{}
	session := NewSession(conn, (&stubServices{}).backupDeps())

	if session.Dispatch([]byte(`{"kind":"request","type":"restore_backup","id":"legacy-restore"}`)) {
		t.Fatal("Dispatch(restore_backup) = true, want unsupported legacy route")
	}
	if len(conn.writes) != 0 {
		t.Fatalf("write count = %d, want 0 for an unsupported route", len(conn.writes))
	}
}

func TestRecoveredLifecycleMessagesDispatchToBackupServices(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()
	restoreID := "0123456789abcdef0123456789abcdef"
	reviewToken := strings.Repeat("a", 64)
	svc := &stubServices{
		recoverBackupResult: adminproto.RecoverBackupResult{
			Success:   true,
			RestoreID: restoreID,
		},
		listRecoveredResult: adminproto.ListRecoveredResult{
			Batches: []adminproto.RecoveredBatchInfo{{
				RestoreID:  restoreID,
				EntryCount: 1,
			}},
		},
		reviewRecoveredResult: adminproto.ReviewRecoveredResult{
			Success:     true,
			RestoreID:   restoreID,
			ReviewToken: reviewToken,
		},
		activateRecoveredResult: adminproto.ActivateRecoveredResult{
			Success:  true,
			Warnings: []string{"skipped bundled template for test.v1: conflict"},
		},
		rollbackRecoveredResult: adminproto.RollbackRecoveredResult{Success: true},
		purgeRecoveredResult:    adminproto.PurgeRecoveredResult{Success: true},
	}
	conn := &queueConn{}
	session := NewSession(conn, svc.backupDeps())
	session.Bind(auth.NewDefaultIdentity("test"), ir)

	dispatchAdminMessage(t, session, protocol.RecoverBackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRecoverBackup, ID: "recover-1"},
		ArchivePath:      "backup.tar.gz",
		Addresses:        []string{"ADDR1"},
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	dispatchAdminMessage(t, session, protocol.ListRecoveredMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListRecovered, ID: "list-recovered-1"},
	})
	dispatchAdminMessage(t, session, protocol.ReviewRecoveredMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeReviewRecovered, ID: "review-1"},
		RestoreID:   restoreID,
	})
	dispatchAdminMessage(t, session, protocol.ActivateRecoveredMessage{
		BaseMessage:                  protocol.BaseMessage{Type: protocol.MsgTypeActivateRecovered, ID: "activate-1"},
		RestoreID:                    restoreID,
		ReviewToken:                  reviewToken,
		AcknowledgeUnattendedSigning: true,
		ReplaceExisting:              true,
	})
	dispatchAdminMessage(t, session, protocol.RollbackRecoveredMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRollbackRecovered, ID: "rollback-1"},
		RestoreID:   restoreID,
	})
	dispatchAdminMessage(t, session, protocol.PurgeRecoveredMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePurgeRecovered, ID: "purge-1"},
		RestoreID:   restoreID,
	})

	if svc.recoverBackupCalls != 1 ||
		svc.listRecoveredCalls != 1 ||
		svc.reviewRecoveredCalls != 1 ||
		svc.activateRecoveredCalls != 1 ||
		svc.rollbackRecoveredCalls != 1 ||
		svc.purgeRecoveredCalls != 1 {
		t.Fatalf("recovery service calls = recover %d list %d review %d activate %d rollback %d purge %d",
			svc.recoverBackupCalls,
			svc.listRecoveredCalls,
			svc.reviewRecoveredCalls,
			svc.activateRecoveredCalls,
			svc.rollbackRecoveredCalls,
			svc.purgeRecoveredCalls,
		)
	}
	if string(svc.lastRecoverBackup.ExportPassphrase) != "export-passphrase" ||
		svc.lastReviewRestoreID != restoreID ||
		!svc.lastActivateRecovered.AcknowledgeUnattendedSigning ||
		!svc.lastActivateRecovered.ReplaceExisting {
		t.Fatalf("projected recovery requests = recover %+v review %q activate %+v",
			svc.lastRecoverBackup,
			svc.lastReviewRestoreID,
			svc.lastActivateRecovered,
		)
	}
	wantTypes := []string{
		protocol.MsgTypeRecoverBackupResult,
		protocol.MsgTypeRecoveredList,
		protocol.MsgTypeReviewRecoveredResult,
		protocol.MsgTypeActivateRecoveredResult,
		protocol.MsgTypeRollbackRecoveredResult,
		protocol.MsgTypePurgeRecoveredResult,
	}
	if len(conn.writes) != len(wantTypes) {
		t.Fatalf("response count = %d, want %d", len(conn.writes), len(wantTypes))
	}
	for i, wantType := range wantTypes {
		var base protocol.BaseMessage
		if err := json.Unmarshal(conn.writes[i], &base); err != nil {
			t.Fatalf("unmarshal response %d: %v", i, err)
		}
		if base.Type != wantType {
			t.Fatalf("response %d type = %q, want %q", i, base.Type, wantType)
		}
	}
	var activated protocol.ActivateRecoveredResultMessage
	if err := json.Unmarshal(conn.writes[3], &activated); err != nil {
		t.Fatalf("unmarshal activation response: %v", err)
	}
	if len(activated.Warnings) != 1 ||
		!strings.Contains(activated.Warnings[0], "skipped bundled template") {
		t.Fatalf("activation warnings = %v", activated.Warnings)
	}
}

func TestRecoveryStatePermitsOnlyRecoveryResolutionHandlers(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetRecovery()
	svc := &stubServices{
		listRecoveredResult: adminproto.ListRecoveredResult{},
	}
	conn := &queueConn{}
	session := NewSession(conn, svc.backupDeps())
	session.Bind(auth.NewDefaultIdentity("test"), ir)

	session.HandleListRecovered("list-recovery")
	if svc.listRecoveredCalls != 1 {
		t.Fatalf("ListRecovered calls = %d, want 1 in recovery state", svc.listRecoveredCalls)
	}
	session.HandleRecoverBackup(&protocol.RecoverBackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRecoverBackup, ID: "recover-blocked"},
		ArchivePath:      "backup.tar.gz",
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	if svc.recoverBackupCalls != 0 {
		t.Fatalf("RecoverBackup calls = %d, want 0 in recovery state", svc.recoverBackupCalls)
	}
	if ir.IsUnlocked() {
		t.Fatal("recovery identity reports unlocked")
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
			name: "recover backup",
			dispatch: func(session *Session) {
				session.HandleRecoverBackup(&protocol.RecoverBackupMessage{
					BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRecoverBackup, ID: "recover-authz"},
					ArchivePath:      "backup.tar.gz",
					ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
				})
			},
			wantRequestID: "recover-authz",
			wantCalls:     func(s *stubServices) int { return s.recoverBackupCalls },
		},
		{
			name: "list recovered",
			dispatch: func(session *Session) {
				session.HandleListRecovered("list-recovered-authz")
			},
			wantRequestID: "list-recovered-authz",
			wantCalls:     func(s *stubServices) int { return s.listRecoveredCalls },
		},
		{
			name: "review recovered",
			dispatch: func(session *Session) {
				session.HandleReviewRecovered(&protocol.ReviewRecoveredMessage{
					BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeReviewRecovered, ID: "review-authz"},
					RestoreID:   "0123456789abcdef0123456789abcdef",
				})
			},
			wantRequestID: "review-authz",
			wantCalls:     func(s *stubServices) int { return s.reviewRecoveredCalls },
		},
		{
			name: "activate recovered",
			dispatch: func(session *Session) {
				session.HandleActivateRecovered(&protocol.ActivateRecoveredMessage{
					BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeActivateRecovered, ID: "activate-authz"},
					RestoreID:   "0123456789abcdef0123456789abcdef",
				})
			},
			wantRequestID: "activate-authz",
			wantCalls:     func(s *stubServices) int { return s.activateRecoveredCalls },
		},
		{
			name: "rollback recovered",
			dispatch: func(session *Session) {
				session.HandleRollbackRecovered(&protocol.RollbackRecoveredMessage{
					BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRollbackRecovered, ID: "rollback-authz"},
					RestoreID:   "0123456789abcdef0123456789abcdef",
				})
			},
			wantRequestID: "rollback-authz",
			wantCalls:     func(s *stubServices) int { return s.rollbackRecoveredCalls },
		},
		{
			name: "purge recovered",
			dispatch: func(session *Session) {
				session.HandlePurgeRecovered(&protocol.PurgeRecoveredMessage{
					BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePurgeRecovered, ID: "purge-authz"},
					RestoreID:   "0123456789abcdef0123456789abcdef",
				})
			},
			wantRequestID: "purge-authz",
			wantCalls:     func(s *stubServices) int { return s.purgeRecoveredCalls },
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
		recoverBackupResult:  adminproto.RecoverBackupResult{ArchiveName: "backup.tar.gz", Success: true},
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

	recoverMsg := &protocol.RecoverBackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRecoverBackup, ID: "recover-zero"},
		ArchivePath:      "backup.tar.gz",
		ExportPassphrase: protocol.NewSensitiveBytes("restore-passphrase"),
	}
	session.HandleRecoverBackup(recoverMsg)
	if string(svc.lastRecoverBackup.ExportPassphrase) != "restore-passphrase" {
		t.Fatalf("service recover passphrase = %q, want original passphrase", string(svc.lastRecoverBackup.ExportPassphrase))
	}
	assertSensitiveBytesZeroed(t, recoverMsg.ExportPassphrase)
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
		recoverBackupResult: adminproto.RecoverBackupResult{
			Success:         true,
			RestoreID:       "0123456789abcdef0123456789abcdef",
			ArchiveChecksum: "archive-digest",
			EntryCount:      1,
		},
		activateRecoveredResult: adminproto.ActivateRecoveredResult{
			Success:                 true,
			RestoreID:               "0123456789abcdef0123456789abcdef",
			Activated:               []adminproto.RecoveredReviewEntry{{Selector: "ADDR1"}},
			ArchiveSHA256:           "archive-digest",
			SourcePolicySHA256:      "source-policy-digest",
			DestinationPolicySHA256: "destination-policy-digest",
			PolicyComparison:        "different",
			ReplaceExisting:         true,
			Resumed:                 true,
		},
		rollbackRecoveredResult: adminproto.RollbackRecoveredResult{
			Success:   true,
			RestoreID: "0123456789abcdef0123456789abcdef",
			KeyCount:  1,
		},
		purgeRecoveredResult: adminproto.PurgeRecoveredResult{
			Success:   true,
			RestoreID: "0123456789abcdef0123456789abcdef",
		},
	}
	audit := &recordingRestoreAudit{}
	svc.onActivateRecovered = func() {
		if len(audit.events) == 0 || audit.events[len(audit.events)-1] != "activation_intent" {
			t.Fatal("activation intent was not audited before the service call")
		}
	}
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
	session.HandleRecoverBackup(&protocol.RecoverBackupMessage{
		BaseMessage:      protocol.BaseMessage{Type: protocol.MsgTypeRecoverBackup, ID: "recover-audit"},
		ArchivePath:      "backup.tar.gz",
		ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	session.HandleActivateRecovered(&protocol.ActivateRecoveredMessage{
		BaseMessage:     protocol.BaseMessage{Type: protocol.MsgTypeActivateRecovered, ID: "activate-audit"},
		RestoreID:       "0123456789abcdef0123456789abcdef",
		ReviewToken:     "review-token",
		ReplaceExisting: true,
	})
	session.HandleRollbackRecovered(&protocol.RollbackRecoveredMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRollbackRecovered, ID: "rollback-audit"},
		RestoreID:   "0123456789abcdef0123456789abcdef",
	})
	session.HandlePurgeRecovered(&protocol.PurgeRecoveredMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePurgeRecovered, ID: "purge-audit"},
		RestoreID:   "0123456789abcdef0123456789abcdef",
	})

	if audit.previewedArchive != "backup.tar.gz" || audit.previewedCount != 1 {
		t.Fatalf("preview audit = archive %q count %d, want backup.tar.gz/1", audit.previewedArchive, audit.previewedCount)
	}
	wantEvents := []string{
		"recovered",
		"activation_intent",
		"activation_resumed",
		"activated",
		"rolled_back",
		"purged",
	}
	if !reflect.DeepEqual(audit.events, wantEvents) {
		t.Fatalf("lifecycle audit events = %v, want %v", audit.events, wantEvents)
	}
	if audit.recovered.ArchiveChecksum != "archive-digest" || audit.recovered.EntryCount != 1 {
		t.Fatalf("recovered audit result = %+v", audit.recovered)
	}
	if audit.activated.DestinationPolicySHA256 != "destination-policy-digest" ||
		!audit.activated.ReplaceExisting {
		t.Fatalf("activated audit result = %+v", audit.activated)
	}
}

func TestActivateRecoveredAbortsWhenDurableIntentAuditFails(t *testing.T) {
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()

	svc := &stubServices{}
	svc.onActivateRecovered = func() {
		t.Fatal("activation service called despite failed durable audit intent")
	}
	audit := &recordingRestoreAudit{intentErr: errors.New("audit disk full")}
	conn := &queueConn{}
	session := NewSession(conn, SessionDeps{
		Backups: svc,
		Audit:   audit,
	})
	session.Bind(auth.NewDefaultIdentity("test"), ir)

	session.HandleActivateRecovered(&protocol.ActivateRecoveredMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeActivateRecovered, ID: "activate-audit-fail"},
		RestoreID:   "0123456789abcdef0123456789abcdef",
		ReviewToken: "review-token",
	})

	if len(conn.writes) != 1 {
		t.Fatalf("writes = %d, want exactly one abort reply", len(conn.writes))
	}
	var reply protocol.ActivateRecoveredResultMessage
	if err := json.Unmarshal(conn.writes[0], &reply); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
	if reply.Success {
		t.Fatal("activation reported success despite failed durable audit intent")
	}
	if reply.Code != protocol.ResultCodeActivationAuditFailed {
		t.Fatalf("code = %q, want %q", reply.Code, protocol.ResultCodeActivationAuditFailed)
	}
	if reply.RestoreID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("restore_id = %q", reply.RestoreID)
	}
}

type recordingRestoreAudit struct {
	recordingAuthorizationAudit

	previewedArchive string
	previewedCount   int
	failedReason     string
	events           []string
	recovered        adminproto.RecoverBackupResult
	activated        adminproto.ActivateRecoveredResult
	intentErr        error
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

func (a *recordingRestoreAudit) LogBackupRecoveredContext(ctx SessionContext, result adminproto.RecoverBackupResult) {
	_ = ctx
	a.events = append(a.events, "recovered")
	a.recovered = result
}

func (a *recordingRestoreAudit) LogBackupRecoveryFailedContext(ctx SessionContext, restoreID, reason string) {
	_ = ctx
	_ = restoreID
	a.events = append(a.events, "recovery_failed")
	a.failedReason = reason
}

func (a *recordingRestoreAudit) LogBackupActivationIntentDurableContext(ctx SessionContext, restoreID string, replaceExisting bool) error {
	_ = ctx
	_ = restoreID
	_ = replaceExisting
	if a.intentErr != nil {
		a.events = append(a.events, "activation_intent_failed")
		return a.intentErr
	}
	a.events = append(a.events, "activation_intent")
	return nil
}

func (a *recordingRestoreAudit) LogBackupActivatedContext(ctx SessionContext, result adminproto.ActivateRecoveredResult) {
	_ = ctx
	a.events = append(a.events, "activated")
	a.activated = result
}

func (a *recordingRestoreAudit) LogBackupActivationFailedContext(ctx SessionContext, result adminproto.ActivateRecoveredResult) {
	_ = ctx
	a.events = append(a.events, "activation_failed")
	a.activated = result
}

func (a *recordingRestoreAudit) LogBackupActivationResumedContext(ctx SessionContext, result adminproto.ActivateRecoveredResult) {
	_ = ctx
	a.events = append(a.events, "activation_resumed")
	a.activated = result
}

func (a *recordingRestoreAudit) LogBackupActivationRolledBackContext(ctx SessionContext, result adminproto.RollbackRecoveredResult) {
	_ = ctx
	_ = result
	a.events = append(a.events, "rolled_back")
}

func (a *recordingRestoreAudit) LogBackupRecoveryPurgedContext(ctx SessionContext, result adminproto.PurgeRecoveredResult) {
	_ = ctx
	_ = result
	a.events = append(a.events, "purged")
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
