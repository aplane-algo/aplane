// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"fmt"
	"github.com/aplane-algo/aplane/internal/adminproto"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

// SendStatus writes the current signer status for the bound identity.
func (s *Session) SendStatus() error {
	ir := s.productOrBoundRuntime()
	return s.WriteJSON(ProtocolStatusMessage(ir.GetState().String(), ir.KeyCount()))
}

// SendError writes a protocol error message.
func (s *Session) SendError(requestID, code, errMsg string) error {
	return s.WriteJSON(ProtocolErrorMessage(requestID, code, errMsg))
}

func (s *Session) handleRevokeToken(msg *protocol.RevokeTokenMessage) {
	ir := s.productOrBoundRuntime()
	if !s.authorize(msg.ID, auth.ActionTokenRevoke, auth.Resource{Type: "token", IdentityID: ir.ID()}) {
		return
	}
	err := s.identityServices.RevokeTokenForIdentity(ir)

	_ = s.WriteJSON(ProtocolRevokeTokenResultMessage(msg.ID, err))
}

func (s *Session) HandleGetAdminSettings(requestID string) {
	ir := s.productOrBoundRuntime()
	if !s.authorize(requestID, auth.ActionSettingsView, auth.Resource{Type: "settings", IdentityID: ir.ID()}) {
		return
	}
	settings := s.settingsServices.BuildAdminSettings(ir)
	_ = s.WriteJSON(ProtocolAdminSettingsMessage(requestID, settings))
}

func (s *Session) HandleUpdateAdminSetting(msg *protocol.UpdateAdminSettingMessage) {
	ir := s.productOrBoundRuntime()
	if !s.authorize(msg.ID, auth.ActionSettingsUpdate, auth.Resource{Type: "settings", IdentityID: ir.ID()}) {
		return
	}
	request := adminproto.UpdateAdminSettingRequest{Key: msg.Key, Value: msg.Value}
	err := s.settingsServices.UpdateAdminSetting(ir, request)
	_ = s.WriteJSON(ProtocolUpdateAdminSettingResultMessage(msg.ID, request, err))
}

func (s *Session) HandleGetPolicySnapshot(msg *protocol.GetPolicySnapshotMessage) {
	ir := s.productOrBoundRuntime()
	if !s.authorize(msg.ID, auth.ActionPolicyView, auth.Resource{Type: "policy", IdentityID: ir.ID()}) {
		return
	}
	snapshot := s.settingsServices.BuildPolicySnapshot(ir, adminproto.NormalizePolicyTarget(msg.Target))
	_ = s.WriteJSON(ProtocolPolicySnapshotMessage(msg.ID, snapshot))
}

func (s *Session) HandleReplacePolicy(msg *protocol.ReplacePolicyMessage) {
	ir := s.productOrBoundRuntime()
	if !s.authorize(msg.ID, auth.ActionPolicyUpdate, auth.Resource{Type: "policy", IdentityID: ir.ID()}) {
		return
	}
	result := s.settingsServices.ReplacePolicy(ir, adminproto.ReplacePolicyRequest{
		Target:                adminproto.NormalizePolicyTarget(msg.Target),
		PolicyYAML:            msg.PolicyYAML,
		ExpectedCurrentSHA256: msg.ExpectedCurrentSHA256,
	})
	_ = s.WriteJSON(ProtocolReplacePolicyResultMessage(msg.ID, result))
}

func (s *Session) HandleValidatePolicy(msg *protocol.ValidatePolicyMessage) {
	ir := s.productOrBoundRuntime()
	if !s.authorize(msg.ID, auth.ActionPolicyView, auth.Resource{Type: "policy", IdentityID: ir.ID()}) {
		return
	}
	result := s.settingsServices.ValidatePolicy(ir, adminproto.ValidatePolicyRequest{
		Target:     adminproto.NormalizePolicyTarget(msg.Target),
		PolicyYAML: msg.PolicyYAML,
	})
	_ = s.WriteJSON(ProtocolValidatePolicyResultMessage(msg.ID, result))
}

func (s *Session) HandleListSentryReferences(requestID string) {
	ir := s.requireBoundRuntime(requestID)
	if ir == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionSentriesView, auth.Resource{Type: "sentry_references", IdentityID: ir.ID()}) {
		return
	}
	if s.inspectionServices == nil {
		_ = s.SendError(requestID, protocol.ErrCodeInternal, "store inspection service unavailable")
		return
	}
	_ = s.WriteJSON(ProtocolSentryReferencesListMessage(requestID, s.inspectionServices.ListSentryReferences(ir)))
}

func (s *Session) HandleGetSentryReference(msg *protocol.GetSentryReferenceMessage) {
	ir := s.requireBoundRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionSentriesView, auth.Resource{Type: "sentry_reference", ID: msg.Name, IdentityID: ir.ID()}) {
		return
	}
	if s.inspectionServices == nil {
		_ = s.SendError(msg.ID, protocol.ErrCodeInternal, "store inspection service unavailable")
		return
	}
	result := s.inspectionServices.GetSentryReference(ir, adminproto.GetSentryReferenceRequest{Name: msg.Name})
	_ = s.WriteJSON(ProtocolSentryReferenceMessage(msg.ID, protocol.MsgTypeSentryReference, result))
}

func (s *Session) HandleImportSentryReference(msg *protocol.ImportSentryReferenceMessage) {
	ir := s.requireBoundRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionSentriesManage, auth.Resource{Type: "sentry_reference", ID: msg.Name, IdentityID: ir.ID()}) {
		return
	}
	if s.inspectionServices == nil {
		_ = s.SendError(msg.ID, protocol.ErrCodeInternal, "store inspection service unavailable")
		return
	}
	result := s.inspectionServices.ImportSentryReference(ir, adminproto.ImportSentryReferenceRequest{Name: msg.Name, EnvelopeJSON: msg.EnvelopeJSON})
	if audit, ok := s.audit.(interface {
		LogSentryReferenceChangedContext(SessionContext, string, string, bool)
	}); ok {
		audit.LogSentryReferenceChangedContext(s.SessionContext(), "import", msg.Name, result.Success)
	}
	_ = s.WriteJSON(ProtocolSentryReferenceMessage(
		msg.ID,
		protocol.MsgTypeImportSentryReferenceResult,
		adminproto.GetSentryReferenceResult(result),
	))
}

func (s *Session) HandleRemoveSentryReference(msg *protocol.RemoveSentryReferenceMessage) {
	ir := s.requireBoundRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionSentriesManage, auth.Resource{Type: "sentry_reference", ID: msg.Name, IdentityID: ir.ID()}) {
		return
	}
	if s.inspectionServices == nil {
		_ = s.SendError(msg.ID, protocol.ErrCodeInternal, "store inspection service unavailable")
		return
	}
	result := s.inspectionServices.RemoveSentryReference(ir, adminproto.RemoveSentryReferenceRequest{Name: msg.Name})
	if audit, ok := s.audit.(interface {
		LogSentryReferenceChangedContext(SessionContext, string, string, bool)
	}); ok {
		audit.LogSentryReferenceChangedContext(s.SessionContext(), "remove", msg.Name, result.Success)
	}
	_ = s.WriteJSON(ProtocolRemoveSentryReferenceResultMessage(msg.ID, result))
}

func (s *Session) HandleExportSentryPublic(msg *protocol.ExportSentryPublicMessage) {
	ir := s.requireBoundRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionSentriesView, auth.Resource{Type: "sentry_public", ID: msg.WitnessKeyID, IdentityID: ir.ID()}) {
		return
	}
	if s.inspectionServices == nil {
		_ = s.SendError(msg.ID, protocol.ErrCodeInternal, "store inspection service unavailable")
		return
	}
	result := s.inspectionServices.ExportSentryPublic(ir, adminproto.ExportSentryPublicRequest{WitnessKeyID: msg.WitnessKeyID})
	_ = s.WriteJSON(ProtocolExportSentryPublicResultMessage(msg.ID, result))
}

func (s *Session) HandleListGenerations(requestID string) {
	ir := s.requireBoundRuntime(requestID)
	if ir == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionGenerationsView, auth.Resource{Type: "generations", IdentityID: ir.ID()}) {
		return
	}
	if s.inspectionServices == nil {
		_ = s.SendError(requestID, protocol.ErrCodeInternal, "store inspection service unavailable")
		return
	}
	_ = s.WriteJSON(ProtocolGenerationsListMessage(requestID, s.inspectionServices.ListGenerations(ir)))
}

func (s *Session) HandleRevokeToken(msg *protocol.RevokeTokenMessage) {
	s.handleRevokeToken(msg)
}

func (s *Session) HandleUnlock(msg *protocol.UnlockMessage) {
	defer msg.Passphrase.Zero()
	ir := s.requireBoundRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityUnlock, auth.Resource{Type: "identity", ID: ir.ID(), IdentityID: ir.ID()}) {
		return
	}

	passphraseBytes := msg.Passphrase.Clone()
	defer zeroBytes(passphraseBytes)

	success, keyCount, errStr, code := s.identityServices.UnlockIdentity(ir, passphraseBytes)
	_ = s.WriteJSON(ProtocolUnlockResultMessage(msg.ID, success, keyCount, errStr, code))
}

func (s *Session) HandleLockIdentity(msg *protocol.LockIdentityMessage) {
	if s.State() != StateAuthenticated {
		_ = s.WriteJSON(ProtocolLockIdentityResultMessage(
			msg.ID,
			protocol.WithCode(protocol.ErrCodeNoIdentityBound, fmt.Errorf("no identity bound to session")),
		))
		return
	}
	ir := s.BoundRuntime()
	if ir == nil {
		_ = s.WriteJSON(ProtocolLockIdentityResultMessage(
			msg.ID,
			protocol.WithCode(protocol.ErrCodeNoIdentityBound, fmt.Errorf("no identity bound to session")),
		))
		return
	}

	resource := auth.Resource{Type: "identity", ID: ir.ID(), IdentityID: ir.ID()}
	identity := s.Identity()
	if s.authorizer != nil && identity == nil {
		_ = s.WriteJSON(ProtocolLockIdentityResultMessage(
			msg.ID,
			protocol.WithCode(protocol.ErrCodeNoIdentityBound, fmt.Errorf("no identity bound to session")),
		))
		return
	}
	if err := s.authorizeIdentity(identity, auth.ActionIdentityLock, resource); err != nil {
		s.logAuthorizationDenied(identity, auth.ActionIdentityLock, resource, err.Error())
		_ = s.WriteJSON(ProtocolLockIdentityResultMessage(
			msg.ID,
			protocol.WithCode(protocol.ErrCodeAuthorizationDenied, fmt.Errorf("authorization denied")),
		))
		return
	}

	ir.FailAllPendingApprovals("identity locked")
	ir.Lock()
	if audit, ok := s.audit.(interface {
		LogIdentityLockedContext(SessionContext, string)
	}); ok {
		audit.LogIdentityLockedContext(s.SessionContext(), msg.Reason)
	}
	_ = s.WriteJSON(ProtocolLockIdentityResultMessage(msg.ID, nil))
}

func (s *Session) HandleBackup(msg *protocol.BackupMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityBackup, auth.Resource{Type: "identity", ID: ir.ID(), IdentityID: ir.ID()}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	exportPassphrase := msg.ExportPassphrase.Clone()
	defer zeroBytes(exportPassphrase)
	defer msg.ExportPassphrase.Zero()
	result := s.backupServices.BackupIdentity(ir, adminproto.BackupIdentityRequest{
		ExportPassphrase: exportPassphrase,
		Addresses:        append([]string(nil), msg.Addresses...),
	})
	if audit, ok := s.audit.(interface {
		LogBackupCreatedContext(SessionContext, string)
		LogBackupFailedContext(SessionContext, string)
	}); ok {
		if result.Success {
			audit.LogBackupCreatedContext(s.SessionContext(), result.ArchivePath)
		} else if result.Error != "" {
			audit.LogBackupFailedContext(s.SessionContext(), result.Error)
		}
	}
	_ = s.WriteJSON(ProtocolBackupResultMessage(msg.ID, result))
}

func (s *Session) HandleListBackups(requestID string) {
	ir := s.requireRecoveryAdminRuntime(requestID)
	if ir == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionIdentityRestore, auth.Resource{Type: "identity", ID: ir.ID(), IdentityID: ir.ID()}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(requestID, "", "backup service unavailable")
		return
	}
	result := s.backupServices.ListBackups(ir)
	_ = s.WriteJSON(ProtocolBackupsListMessage(requestID, result))
}

func (s *Session) HandleDeleteBackup(msg *protocol.DeleteBackupMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityBackup, auth.Resource{Type: "identity", ID: ir.ID(), IdentityID: ir.ID()}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	result := s.backupServices.DeleteBackup(ir, adminproto.DeleteBackupRequest{ArchivePath: msg.ArchivePath})
	_ = s.WriteJSON(ProtocolDeleteBackupResultMessage(msg.ID, result))
}

func (s *Session) HandleBeginBackupImport(msg *protocol.BeginBackupImportMessage) {
	ir := s.requireRecoveryAdminRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "backup", ID: msg.FileName, IdentityID: ir.ID()}) {
		return
	}
	result := s.backupServices.BeginBackupImport(ir, adminproto.BeginBackupImportRequest{FileName: msg.FileName})
	_ = s.WriteJSON(ProtocolBeginBackupImportResultMessage(msg.ID, result))
}

func (s *Session) HandleAppendBackupImport(msg *protocol.AppendBackupImportMessage) {
	ir := s.requireRecoveryAdminRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "backup_upload", ID: msg.UploadID, IdentityID: ir.ID()}) {
		return
	}
	result := s.backupServices.AppendBackupImport(ir, adminproto.AppendBackupImportRequest{UploadID: msg.UploadID, Offset: msg.Offset, Data: msg.Data})
	_ = s.WriteJSON(ProtocolAppendBackupImportResultMessage(msg.ID, result))
}

func (s *Session) HandleCommitBackupImport(msg *protocol.CommitBackupImportMessage) {
	ir := s.requireRecoveryAdminRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "backup", ID: msg.FileName, IdentityID: ir.ID()}) {
		return
	}
	result := s.backupServices.CommitBackupImport(ir, adminproto.CommitBackupImportRequest{
		UploadID: msg.UploadID, FileName: msg.FileName,
		ExpectedSize: msg.ExpectedSize, ExpectedSHA256: msg.ExpectedSHA256,
	})
	if result.Success {
		if audit, ok := s.audit.(interface {
			LogBackupImportedContext(SessionContext, string, int64)
		}); ok {
			audit.LogBackupImportedContext(s.SessionContext(), result.Backup.FileName, result.Backup.Size)
		}
	}
	_ = s.WriteJSON(ProtocolCommitBackupImportResultMessage(msg.ID, result))
}

func (s *Session) HandleAbortBackupImport(msg *protocol.AbortBackupImportMessage) {
	ir := s.requireBoundRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "backup_upload", ID: msg.UploadID, IdentityID: ir.ID()}) {
		return
	}
	result := s.backupServices.AbortBackupImport(ir, adminproto.AbortBackupImportRequest{UploadID: msg.UploadID})
	_ = s.WriteJSON(ProtocolAbortBackupImportResultMessage(msg.ID, result))
}

func (s *Session) HandleReadBackupChunk(msg *protocol.ReadBackupChunkMessage) {
	ir := s.requireBoundRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityBackup, auth.Resource{Type: "backup", ID: msg.FileName, IdentityID: ir.ID()}) {
		return
	}
	result := s.backupServices.ReadBackupChunk(ir, adminproto.ReadBackupChunkRequest{FileName: msg.FileName, Offset: msg.Offset})
	_ = s.WriteJSON(ProtocolBackupChunkMessage(msg.ID, result))
}

func (s *Session) HandleChangeStorePassphrase(msg *protocol.ChangeStorePassphraseMessage) {
	defer msg.CurrentPassphrase.Zero()
	defer msg.NewPassphrase.Zero()
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityPassphrase, auth.Resource{Type: "identity", ID: ir.ID(), IdentityID: ir.ID()}) {
		return
	}
	if s.identityServices == nil {
		_ = s.SendError(msg.ID, "", "identity service unavailable")
		return
	}
	currentPassphrase := msg.CurrentPassphrase.Clone()
	newPassphrase := msg.NewPassphrase.Clone()
	defer zeroBytes(currentPassphrase)
	defer zeroBytes(newPassphrase)
	result := s.identityServices.ChangeStorePassphrase(ir, adminproto.ChangeStorePassphraseRequest{
		CurrentPassphrase: currentPassphrase,
		NewPassphrase:     newPassphrase,
	})
	_ = s.WriteJSON(ProtocolChangeStorePassphraseResultMessage(msg.ID, result))
}

func (s *Session) HandlePreviewRestore(msg *protocol.PreviewRestoreMessage) {
	ir := s.requireRecoveryAdminRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "identity", ID: ir.ID(), IdentityID: ir.ID()}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	exportPassphrase := msg.ExportPassphrase.Clone()
	defer zeroBytes(exportPassphrase)
	defer msg.ExportPassphrase.Zero()
	result := s.backupServices.PreviewRestore(ir, adminproto.PreviewRestoreRequest{
		ArchivePath:      msg.ArchivePath,
		ExportPassphrase: exportPassphrase,
	})
	if audit, ok := s.audit.(interface {
		LogBackupRestorePreviewedContext(SessionContext, string, int)
		LogBackupRestorePreviewFailedContext(SessionContext, string)
	}); ok {
		switch {
		case result.Error != "":
			audit.LogBackupRestorePreviewFailedContext(s.SessionContext(), result.Error)
		case len(result.Errors) > 0:
			audit.LogBackupRestorePreviewFailedContext(s.SessionContext(), "restore preview returned key errors")
		default:
			audit.LogBackupRestorePreviewedContext(s.SessionContext(), result.ArchivePath, len(result.Keys))
		}
	}
	_ = s.WriteJSON(ProtocolRestorePreviewMessage(msg.ID, result))
}

func (s *Session) HandleRestoreBackup(msg *protocol.RestoreBackupMessage) {
	ir := s.requireRecoveryAdminRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "identity", ID: ir.ID(), IdentityID: ir.ID()}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	audit, ok := s.audit.(interface {
		LogCredentialRestoreIntentDurableContext(SessionContext, string, string, bool) error
	})
	if !ok {
		_ = s.WriteJSON(ProtocolRestoreBackupResultMessage(msg.ID, adminproto.RestoreBackupResult{
			OperationID: msg.ID,
			Code:        protocol.ResultCodeRestoreAuditFailed,
			Error:       "restore aborted: durable restore-intent audit is unavailable",
		}))
		msg.ExportPassphrase.Zero()
		return
	}
	if err := audit.LogCredentialRestoreIntentDurableContext(
		s.SessionContext(), msg.ID, msg.ArchivePath, msg.ReplaceExisting,
	); err != nil {
		_ = s.WriteJSON(ProtocolRestoreBackupResultMessage(msg.ID, adminproto.RestoreBackupResult{
			OperationID: msg.ID,
			Code:        protocol.ResultCodeRestoreAuditFailed,
			Error:       fmt.Sprintf("restore aborted: durable restore-intent audit failed: %v", err),
		}))
		msg.ExportPassphrase.Zero()
		return
	}
	exportPassphrase := msg.ExportPassphrase.Clone()
	defer zeroBytes(exportPassphrase)
	defer msg.ExportPassphrase.Zero()
	result := s.backupServices.RestoreBackup(ir, adminproto.RestoreBackupRequest{
		OperationID:      msg.ID,
		ArchivePath:      msg.ArchivePath,
		Addresses:        append([]string(nil), msg.Addresses...),
		ExportPassphrase: exportPassphrase,
		ReplaceExisting:  msg.ReplaceExisting,
	})
	if audit, ok := s.audit.(interface {
		LogCredentialRestoreContext(SessionContext, adminproto.RestoreBackupResult)
	}); ok {
		audit.LogCredentialRestoreContext(s.SessionContext(), result)
	}
	_ = s.WriteJSON(ProtocolRestoreBackupResultMessage(msg.ID, result))
}

func (s *Session) HandleRollbackRestore(msg *protocol.RollbackRestoreMessage) {
	ir := s.requireRecoveryAdminRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "identity", ID: ir.ID(), IdentityID: ir.ID()}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	result := s.backupServices.RollbackRestore(ir, adminproto.RollbackRestoreRequest{
		OperationID: msg.ID,
	})
	if audit, ok := s.audit.(interface {
		LogCredentialRestoreRollbackContext(SessionContext, adminproto.RollbackRestoreResult)
	}); ok {
		audit.LogCredentialRestoreRollbackContext(s.SessionContext(), result)
	}
	_ = s.WriteJSON(ProtocolRollbackRestoreResultMessage(msg.ID, result))
}

func (s *Session) HandleReconcileStore(requestID string) {
	ir := s.requireRecoveryAdminRuntime(requestID)
	if ir == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionIdentityRestore, auth.Resource{Type: "identity", ID: ir.ID(), IdentityID: ir.ID()}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(requestID, "", "backup service unavailable")
		return
	}
	_ = s.WriteJSON(ProtocolReconcileStoreResultMessage(requestID, s.backupServices.ReconcileStore(ir)))
}

func (s *Session) HandleListKeys(requestID string) {
	ir := s.requireUnlockedRuntime(requestID)
	if ir == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionKeysView, auth.Resource{Type: "keys", IdentityID: ir.ID()}) {
		return
	}

	keys, err := s.keyServices.ListKeys(ir)
	if err != nil {
		_ = s.SendError(requestID, "", err.Error())
		return
	}

	_ = s.WriteJSON(ProtocolKeysListMessage(requestID, keys))
}

func (s *Session) HandleGetKeyDetails(msg *protocol.GetKeyDetailsMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionKeysView, auth.Resource{Type: "key", ID: msg.Address, IdentityID: ir.ID()}) {
		return
	}

	details := s.keyServices.GetKeyDetails(ir, adminproto.GetKeyDetailsRequest{Address: msg.Address})
	_ = s.WriteJSON(ProtocolKeyDetailsMessage(msg.ID, details))
}

func (s *Session) HandleListLibraryTemplates(requestID string) {
	ir := s.requireUnlockedRuntime(requestID)
	if ir == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionTemplatesView, auth.Resource{Type: "templates", IdentityID: ir.ID()}) {
		return
	}
	result := s.templateServices.ListLibraryTemplates(ir)
	_ = s.WriteJSON(ProtocolLibraryTemplatesMessage(requestID, result))
}

func (s *Session) HandleInstallLibraryTemplate(msg *protocol.InstallLibraryTemplateMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionTemplatesInstall, auth.Resource{Type: "template", ID: msg.KeyType, IdentityID: ir.ID()}) {
		return
	}
	result := s.templateServices.InstallLibraryTemplate(ir, adminproto.InstallLibraryTemplateRequest{
		KeyType:      msg.KeyType,
		TemplateType: msg.TemplateType,
	})
	_ = s.WriteJSON(ProtocolInstallLibraryTemplateResultMessage(msg.ID, result))
}

func (s *Session) HandleListInstalledTemplates(requestID string) {
	ir := s.requireUnlockedRuntime(requestID)
	if ir == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionTemplatesView, auth.Resource{Type: "templates", IdentityID: ir.ID()}) {
		return
	}
	result := s.templateServices.ListInstalledTemplates(ir)
	_ = s.WriteJSON(ProtocolInstalledTemplatesMessage(requestID, result))
}

func (s *Session) HandleShowInstalledTemplate(msg *protocol.ShowInstalledTemplateMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionTemplatesView, auth.Resource{Type: "template", ID: msg.KeyType, IdentityID: ir.ID()}) {
		return
	}
	result := s.templateServices.ShowInstalledTemplate(ir, adminproto.ShowInstalledTemplateRequest{
		KeyType: msg.KeyType,
	})
	_ = s.WriteJSON(ProtocolShowInstalledTemplateResultMessage(msg.ID, result))
}

func (s *Session) HandleShowLibraryTemplate(msg *protocol.ShowLibraryTemplateMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionTemplatesView, auth.Resource{Type: "template", ID: msg.KeyType, IdentityID: ir.ID()}) {
		return
	}
	result := s.templateServices.ShowLibraryTemplate(ir, adminproto.ShowLibraryTemplateRequest{
		KeyType:      msg.KeyType,
		TemplateType: msg.TemplateType,
	})
	_ = s.WriteJSON(ProtocolShowLibraryTemplateResultMessage(msg.ID, result))
}

func (s *Session) HandleImportInstalledTemplate(msg *protocol.ImportInstalledTemplateMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionTemplatesInstall, auth.Resource{Type: "template", IdentityID: ir.ID()}) {
		return
	}
	result := s.templateServices.ImportInstalledTemplate(ir, adminproto.ImportInstalledTemplateRequest{
		TemplateYAML: []byte(msg.TemplateYAML),
	})
	_ = s.WriteJSON(ProtocolImportInstalledTemplateResultMessage(msg.ID, result))
}

func (s *Session) HandleRemoveInstalledTemplate(msg *protocol.RemoveInstalledTemplateMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionTemplatesRemove, auth.Resource{Type: "template", ID: msg.KeyType, IdentityID: ir.ID()}) {
		return
	}
	result := s.templateServices.RemoveInstalledTemplate(ir, adminproto.RemoveInstalledTemplateRequest{
		KeyType: msg.KeyType,
	})
	_ = s.WriteJSON(ProtocolRemoveInstalledTemplateResultMessage(msg.ID, result))
}

func (s *Session) HandleActivateKeyType(msg *protocol.ActivateKeyTypeMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionKeyTypesActivate, auth.Resource{Type: "keytype", ID: msg.KeyType, IdentityID: ir.ID()}) {
		return
	}
	result := s.templateServices.ActivateKeyType(ir, adminproto.ActivateKeyTypeRequest{
		KeyType: msg.KeyType,
	})
	_ = s.WriteJSON(ProtocolActivateKeyTypeResultMessage(msg.ID, result))
}

func (s *Session) HandleDeactivateKeyType(msg *protocol.DeactivateKeyTypeMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionKeyTypesDeactivate, auth.Resource{Type: "keytype", ID: msg.KeyType, IdentityID: ir.ID()}) {
		return
	}
	result := s.templateServices.DeactivateKeyType(ir, adminproto.DeactivateKeyTypeRequest{
		KeyType: msg.KeyType,
	})
	_ = s.WriteJSON(ProtocolDeactivateKeyTypeResultMessage(msg.ID, result))
}

func (s *Session) HandleListKeyTypes(requestID string) {
	ir := s.requireBoundRuntime(requestID)
	if ir == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionKeyTypesView, auth.Resource{Type: "keytypes", IdentityID: ir.ID()}) {
		return
	}
	result := s.templateServices.ListKeyTypes(ir)
	_ = s.WriteJSON(ProtocolKeyTypesMessage(requestID, result))
}

func (s *Session) HandleSignResponse(msg *protocol.SignResponseMessage) {
	if ir := s.BoundRuntime(); ir != nil {
		if !s.authorize(msg.ID, auth.ActionSignApprove, auth.Resource{Type: "sign_request", ID: msg.ID, IdentityID: ir.ID()}) {
			return
		}
		ctx := s.SessionContext()
		approver := ctx.ApproverPrincipal.ID
		if approver == "" {
			approver = ctx.AdminPrincipal.ID
		}
		ir.HandleSignApprovalResponse(&signerapproval.SignResponse{
			ID:                msg.ID,
			Approved:          msg.Approved,
			Reason:            msg.Reason,
			ApproverPrincipal: approver,
		})
	}
}

func (s *Session) HandleTokenProvisioningResponse(msg *protocol.TokenProvisioningResponseMessage) {
	if ir := s.BoundRuntime(); ir != nil {
		if !s.authorize(msg.ID, auth.ActionTokenProvision, auth.Resource{Type: "token_provisioning", ID: msg.ID, IdentityID: ir.ID()}) {
			return
		}
		ir.HandleTokenProvisioningApprovalResponse(&signerapproval.TokenProvisioningResponse{
			ID:       msg.ID,
			Approved: msg.Approved,
			Reason:   msg.Reason,
		})
	}
}

func (s *Session) HandleGenerateKey(msg *protocol.GenerateKeyMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	resource := auth.Resource{Type: "key", IdentityID: ir.ID()}
	if !s.authorize(msg.ID, auth.ActionKeysGenerate, resource) {
		return
	}
	gen := s.keyServices.GenerateKey(s.Context(), ir, adminproto.GenerateKeyRequest{
		KeyType:    msg.KeyType,
		Name:       msg.Name,
		Parameters: msg.Parameters,
	})
	_ = s.WriteJSON(ProtocolGenerateResultMessage(msg.ID, gen))
}

func (s *Session) HandleDeleteKey(msg *protocol.DeleteKeyMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionKeysDelete, auth.Resource{Type: "key", ID: msg.Address, IdentityID: ir.ID()}) {
		return
	}
	del := s.keyServices.DeleteKey(ir, adminproto.DeleteKeyRequest{Address: msg.Address})
	_ = s.WriteJSON(ProtocolDeleteResultMessage(msg.ID, del))
}

func (s *Session) HandleExportKey(msg *protocol.ExportKeyMessage) {
	msg.Passphrase.Zero()
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	resource := auth.Resource{Type: "key", ID: msg.Address, IdentityID: ir.ID()}
	if !s.authorize(msg.ID, auth.ActionKeysExport, resource) {
		return
	}
	const reason = "key export is disabled; use encrypted backups for recovery"
	s.logAuthorizationDenied(s.Identity(), auth.ActionKeysExport, resource, reason)
	_ = s.SendError(msg.ID, protocol.ErrCodeAuthorizationDenied, reason)
}

func (s *Session) HandleImportKey(msg *protocol.ImportKeyMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
	if ir == nil {
		return
	}
	resource := auth.Resource{Type: "key", IdentityID: ir.ID()}
	if !s.authorize(msg.ID, auth.ActionKeysImport, resource) {
		return
	}
	if !s.requireLocalImportTransport(msg.ID, auth.ActionKeysImport, resource) {
		return
	}
	imp := s.keyServices.ImportKey(ir, adminproto.ImportKeyRequest{
		KeyType:    msg.KeyType,
		Mnemonic:   msg.Mnemonic,
		Parameters: msg.Parameters,
	})
	_ = s.WriteJSON(ProtocolImportResultMessage(msg.ID, imp))
}

func (s *Session) requireLocalImportTransport(requestID string, action auth.Action, resource auth.Resource) bool {
	if s.Transport() == TransportIPC {
		return true
	}
	const reason = "key import is only available on local AP Admin"
	s.logAuthorizationDenied(s.Identity(), action, resource, reason)
	_ = s.SendError(requestID, protocol.ErrCodeAuthorizationDenied, reason)
	return false
}
