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
	if !s.authorize(msg.ID, auth.ActionTokenRevoke, auth.Resource{Type: "token"}) {
		return
	}
	err := s.productServices.RevokeProductToken()

	_ = s.WriteJSON(ProtocolRevokeTokenResultMessage(msg.ID, err))
}

func (s *Session) HandleGetAdminSettings(requestID string) {
	if !s.authorize(requestID, auth.ActionSettingsView, auth.Resource{Type: "settings"}) {
		return
	}
	settings := s.settingsServices.BuildAdminSettings()
	_ = s.WriteJSON(ProtocolAdminSettingsMessage(requestID, settings))
}

func (s *Session) HandleUpdateAdminSetting(msg *protocol.UpdateAdminSettingMessage) {
	if !s.authorize(msg.ID, auth.ActionSettingsUpdate, auth.Resource{Type: "settings"}) {
		return
	}
	request := adminproto.UpdateAdminSettingRequest{Key: msg.Key, Value: msg.Value}
	err := s.settingsServices.UpdateAdminSetting(request)
	_ = s.WriteJSON(ProtocolUpdateAdminSettingResultMessage(msg.ID, request, err))
}

func (s *Session) HandleGetPolicySnapshot(msg *protocol.GetPolicySnapshotMessage) {
	if !s.authorize(msg.ID, auth.ActionPolicyView, auth.Resource{Type: "policy"}) {
		return
	}
	snapshot := s.settingsServices.BuildPolicySnapshot(adminproto.NormalizePolicyTarget(msg.Target))
	_ = s.WriteJSON(ProtocolPolicySnapshotMessage(msg.ID, snapshot))
}

func (s *Session) HandleReplacePolicy(msg *protocol.ReplacePolicyMessage) {
	if !s.authorize(msg.ID, auth.ActionPolicyUpdate, auth.Resource{Type: "policy"}) {
		return
	}
	result := s.settingsServices.ReplacePolicy(adminproto.ReplacePolicyRequest{
		Target:                adminproto.NormalizePolicyTarget(msg.Target),
		PolicyYAML:            msg.PolicyYAML,
		ExpectedCurrentSHA256: msg.ExpectedCurrentSHA256,
	})
	_ = s.WriteJSON(ProtocolReplacePolicyResultMessage(msg.ID, result))
}

func (s *Session) HandleValidatePolicy(msg *protocol.ValidatePolicyMessage) {
	if !s.authorize(msg.ID, auth.ActionPolicyView, auth.Resource{Type: "policy"}) {
		return
	}
	result := s.settingsServices.ValidatePolicy(adminproto.ValidatePolicyRequest{
		Target:     adminproto.NormalizePolicyTarget(msg.Target),
		PolicyYAML: msg.PolicyYAML,
	})
	_ = s.WriteJSON(ProtocolValidatePolicyResultMessage(msg.ID, result))
}

func (s *Session) HandleListSentryReferences(requestID string) {
	if s.requireBoundRuntime(requestID) == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionSentriesView, auth.Resource{Type: "sentry_references"}) {
		return
	}
	if s.inspectionServices == nil {
		_ = s.SendError(requestID, protocol.ErrCodeInternal, "store inspection service unavailable")
		return
	}
	_ = s.WriteJSON(ProtocolSentryReferencesListMessage(requestID, s.inspectionServices.ListSentryReferences()))
}

func (s *Session) HandleGetSentryReference(msg *protocol.GetSentryReferenceMessage) {
	if s.requireBoundRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionSentriesView, auth.Resource{Type: "sentry_reference", ID: msg.Name}) {
		return
	}
	if s.inspectionServices == nil {
		_ = s.SendError(msg.ID, protocol.ErrCodeInternal, "store inspection service unavailable")
		return
	}
	result := s.inspectionServices.GetSentryReference(adminproto.GetSentryReferenceRequest{Name: msg.Name})
	_ = s.WriteJSON(ProtocolSentryReferenceMessage(msg.ID, protocol.MsgTypeSentryReference, result))
}

func (s *Session) HandleImportSentryReference(msg *protocol.ImportSentryReferenceMessage) {
	// Reference aliases select the witness public key embedded during guarded
	// key generation, so mutation shares key generation's unlocked interlock.
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionSentriesManage, auth.Resource{Type: "sentry_reference", ID: msg.Name}) {
		return
	}
	if s.inspectionServices == nil {
		_ = s.SendError(msg.ID, protocol.ErrCodeInternal, "store inspection service unavailable")
		return
	}
	result := s.inspectionServices.ImportSentryReference(adminproto.ImportSentryReferenceRequest{Name: msg.Name, EnvelopeJSON: msg.EnvelopeJSON})
	if audit, ok := s.audit.(interface {
		LogSentryReferenceChangedContext(SessionContext, string, string, string, string, bool)
	}); ok {
		audit.LogSentryReferenceChangedContext(s.SessionContext(), "import", msg.Name, result.Reference.ComponentKey, result.Reference.MigrationOrigin, result.Success)
	}
	_ = s.WriteJSON(ProtocolSentryReferenceMessage(
		msg.ID,
		protocol.MsgTypeImportSentryReferenceResult,
		adminproto.GetSentryReferenceResult(result),
	))
}

func (s *Session) HandleRemoveSentryReference(msg *protocol.RemoveSentryReferenceMessage) {
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionSentriesManage, auth.Resource{Type: "sentry_reference", ID: msg.Name}) {
		return
	}
	if s.inspectionServices == nil {
		_ = s.SendError(msg.ID, protocol.ErrCodeInternal, "store inspection service unavailable")
		return
	}
	result := s.inspectionServices.RemoveSentryReference(adminproto.RemoveSentryReferenceRequest{Name: msg.Name})
	if audit, ok := s.audit.(interface {
		LogSentryReferenceChangedContext(SessionContext, string, string, string, string, bool)
	}); ok {
		audit.LogSentryReferenceChangedContext(s.SessionContext(), "remove", msg.Name, result.ComponentKey, "", result.Success)
	}
	_ = s.WriteJSON(ProtocolRemoveSentryReferenceResultMessage(msg.ID, result))
}

func (s *Session) HandleExportSentryPublic(msg *protocol.ExportSentryPublicMessage) {
	if s.requireBoundRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionSentriesView, auth.Resource{Type: "sentry_public", ID: msg.WitnessKeyID}) {
		return
	}
	if s.inspectionServices == nil {
		_ = s.SendError(msg.ID, protocol.ErrCodeInternal, "store inspection service unavailable")
		return
	}
	result := s.inspectionServices.ExportSentryPublic(adminproto.ExportSentryPublicRequest{WitnessKeyID: msg.WitnessKeyID})
	_ = s.WriteJSON(ProtocolExportSentryPublicResultMessage(msg.ID, result))
}

func (s *Session) HandleListGenerations(requestID string) {
	if s.requireBoundRuntime(requestID) == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionGenerationsView, auth.Resource{Type: "generations"}) {
		return
	}
	if s.inspectionServices == nil {
		_ = s.SendError(requestID, protocol.ErrCodeInternal, "store inspection service unavailable")
		return
	}
	_ = s.WriteJSON(ProtocolGenerationsListMessage(requestID, s.inspectionServices.ListGenerations()))
}

func (s *Session) HandleRevokeToken(msg *protocol.RevokeTokenMessage) {
	s.handleRevokeToken(msg)
}

func (s *Session) HandleUnlock(msg *protocol.UnlockMessage) {
	defer msg.Passphrase.Zero()
	if s.requireBoundRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityUnlock, auth.Resource{Type: "identity"}) {
		return
	}

	passphraseBytes := msg.Passphrase.Clone()
	defer zeroBytes(passphraseBytes)

	success, keyCount, errStr, code := s.productServices.UnlockIdentity(passphraseBytes)
	_ = s.WriteJSON(ProtocolUnlockResultMessage(msg.ID, success, keyCount, errStr, code))
}

func (s *Session) HandleLockIdentity(msg *protocol.LockIdentityMessage) {
	if s.State() != StateAuthenticated {
		_ = s.WriteJSON(ProtocolLockIdentityResultMessage(
			msg.ID,
			protocol.WithCode(protocol.ErrCodeNoRuntimeBound, fmt.Errorf("no product runtime bound to session")),
		))
		return
	}
	ir := s.BoundRuntime()
	if ir == nil {
		_ = s.WriteJSON(ProtocolLockIdentityResultMessage(
			msg.ID,
			protocol.WithCode(protocol.ErrCodeNoRuntimeBound, fmt.Errorf("no product runtime bound to session")),
		))
		return
	}

	resource := auth.Resource{Type: "identity"}
	identity := s.Identity()
	if s.authorizer != nil && identity == nil {
		_ = s.WriteJSON(ProtocolLockIdentityResultMessage(
			msg.ID,
			protocol.WithCode(protocol.ErrCodeNoRuntimeBound, fmt.Errorf("no product runtime bound to session")),
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
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityBackup, auth.Resource{Type: "identity"}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	exportPassphrase := msg.ExportPassphrase.Clone()
	defer zeroBytes(exportPassphrase)
	defer msg.ExportPassphrase.Zero()
	result := s.backupServices.BackupIdentity(adminproto.BackupIdentityRequest{
		ExportPassphrase: exportPassphrase,
		Addresses:        append([]string(nil), msg.Addresses...),
	})
	if result.Success {
		if audit, ok := s.audit.(interface {
			LogBackupCreatedContext(SessionContext, string)
		}); ok {
			audit.LogBackupCreatedContext(s.SessionContext(), result.ArchivePath)
		}
	} else if result.Error != "" {
		if audit, ok := s.audit.(interface {
			LogBackupFailedContext(SessionContext, string)
		}); ok {
			audit.LogBackupFailedContext(s.SessionContext(), result.Error)
		}
	}
	_ = s.WriteJSON(ProtocolBackupResultMessage(msg.ID, result))
}

func (s *Session) HandleListBackups(requestID string) {
	if s.requireRecoveryAdminRuntime(requestID) == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionIdentityRestore, auth.Resource{Type: "identity"}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(requestID, "", "backup service unavailable")
		return
	}
	result := s.backupServices.ListBackups()
	_ = s.WriteJSON(ProtocolBackupsListMessage(requestID, result))
}

func (s *Session) HandleDeleteBackup(msg *protocol.DeleteBackupMessage) {
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityBackup, auth.Resource{Type: "identity"}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	result := s.backupServices.DeleteBackup(adminproto.DeleteBackupRequest{ArchivePath: msg.ArchivePath})
	_ = s.WriteJSON(ProtocolDeleteBackupResultMessage(msg.ID, result))
}

func (s *Session) HandleBeginBackupImport(msg *protocol.BeginBackupImportMessage) {
	if s.requireRecoveryAdminRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "backup", ID: msg.FileName}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	result := s.backupServices.BeginBackupImport(adminproto.BeginBackupImportRequest{
		FileName: msg.FileName,
	})
	_ = s.WriteJSON(ProtocolBeginBackupImportResultMessage(msg.ID, result))
}

func (s *Session) HandleAppendBackupImport(msg *protocol.AppendBackupImportMessage) {
	if s.requireRecoveryAdminRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "backup_upload", ID: msg.UploadID}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	result := s.backupServices.AppendBackupImport(adminproto.AppendBackupImportRequest{UploadID: msg.UploadID, Offset: msg.Offset, Data: msg.Data})
	_ = s.WriteJSON(ProtocolAppendBackupImportResultMessage(msg.ID, result))
}

func (s *Session) HandleCommitBackupImport(msg *protocol.CommitBackupImportMessage) {
	defer msg.ExportPassphrase.Zero()
	if s.requireRecoveryAdminRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "backup", ID: msg.FileName}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	result := s.backupServices.CommitBackupImport(adminproto.CommitBackupImportRequest{
		UploadID: msg.UploadID, FileName: msg.FileName,
		ExpectedSize: msg.ExpectedSize, ExpectedSHA256: msg.ExpectedSHA256,
		ExportPassphrase: msg.ExportPassphrase.Clone(),
	})
	if result.Success {
		if audit, ok := s.audit.(interface {
			LogBackupImportedContext(SessionContext, string, int64)
		}); ok {
			audit.LogBackupImportedContext(s.SessionContext(), result.Backup.FileName, result.Backup.Size)
		}
	} else if result.Error != "" {
		if audit, ok := s.audit.(interface {
			LogBackupFailedContext(SessionContext, string)
		}); ok {
			audit.LogBackupFailedContext(s.SessionContext(), "backup import failed: "+result.Error)
		}
	}
	_ = s.WriteJSON(ProtocolCommitBackupImportResultMessage(msg.ID, result))
}

func (s *Session) HandleAbortBackupImport(msg *protocol.AbortBackupImportMessage) {
	// Abort removes only an unpublished, path-confined .part upload. Keep this
	// authorized cleanup available while the bound identity is locked so a
	// failed import does not require unlocking merely to discard residue.
	if s.requireBoundRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "backup_upload", ID: msg.UploadID}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	result := s.backupServices.AbortBackupImport(adminproto.AbortBackupImportRequest{UploadID: msg.UploadID})
	_ = s.WriteJSON(ProtocolAbortBackupImportResultMessage(msg.ID, result))
}

func (s *Session) HandleReadBackupChunk(msg *protocol.ReadBackupChunkMessage) {
	if s.requireRecoveryAdminRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityBackup, auth.Resource{Type: "backup", ID: msg.FileName}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	result := s.backupServices.ReadBackupChunk(adminproto.ReadBackupChunkRequest{FileName: msg.FileName, Offset: msg.Offset})
	if result.Success {
		if audit, ok := s.audit.(interface {
			LogBackupExportStartedContext(SessionContext, string)
		}); ok {
			if s.markBackupExportChunk(result.FileName, result.Offset, result.EOF) {
				audit.LogBackupExportStartedContext(s.SessionContext(), result.FileName)
			}
		}
	} else if result.Error != "" {
		if audit, ok := s.audit.(interface {
			LogBackupFailedContext(SessionContext, string)
		}); ok {
			audit.LogBackupFailedContext(s.SessionContext(), "backup export failed: "+result.Error)
		}
	}
	_ = s.WriteJSON(ProtocolBackupChunkMessage(msg.ID, result))
}

func (s *Session) HandleChangeStorePassphrase(msg *protocol.ChangeStorePassphraseMessage) {
	defer msg.CurrentPassphrase.Zero()
	defer msg.NewPassphrase.Zero()
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityPassphrase, auth.Resource{Type: "identity"}) {
		return
	}
	if s.productServices == nil {
		_ = s.SendError(msg.ID, "", "identity service unavailable")
		return
	}
	currentPassphrase := msg.CurrentPassphrase.Clone()
	newPassphrase := msg.NewPassphrase.Clone()
	defer zeroBytes(currentPassphrase)
	defer zeroBytes(newPassphrase)
	result := s.productServices.ChangeStorePassphrase(adminproto.ChangeStorePassphraseRequest{
		CurrentPassphrase: currentPassphrase,
		NewPassphrase:     newPassphrase,
	})
	_ = s.WriteJSON(ProtocolChangeStorePassphraseResultMessage(msg.ID, result))
}

func (s *Session) HandlePreviewRestore(msg *protocol.PreviewRestoreMessage) {
	if s.requireRecoveryAdminRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "identity"}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	exportPassphrase := msg.ExportPassphrase.Clone()
	defer zeroBytes(exportPassphrase)
	defer msg.ExportPassphrase.Zero()
	result := s.backupServices.PreviewRestore(adminproto.PreviewRestoreRequest{
		ArchivePath:      msg.ArchivePath,
		ExportPassphrase: exportPassphrase,
	})
	switch {
	case result.Error != "":
		if audit, ok := s.audit.(interface {
			LogBackupRestorePreviewFailedContext(SessionContext, string)
		}); ok {
			audit.LogBackupRestorePreviewFailedContext(s.SessionContext(), result.Error)
		}
	case len(result.Errors) > 0:
		if audit, ok := s.audit.(interface {
			LogBackupRestorePreviewFailedContext(SessionContext, string)
		}); ok {
			audit.LogBackupRestorePreviewFailedContext(s.SessionContext(), "restore preview returned key errors")
		}
	default:
		if audit, ok := s.audit.(interface {
			LogBackupRestorePreviewedContext(SessionContext, string, int)
		}); ok {
			audit.LogBackupRestorePreviewedContext(s.SessionContext(), result.ArchivePath, len(result.Keys))
		}
	}
	_ = s.WriteJSON(ProtocolRestorePreviewMessage(msg.ID, result))
}

func (s *Session) HandleRestoreBackup(msg *protocol.RestoreBackupMessage) {
	if s.requireRecoveryAdminRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "identity"}) {
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
	result := s.backupServices.RestoreBackup(adminproto.RestoreBackupRequest{
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
	if s.requireRecoveryAdminRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionIdentityRestore, auth.Resource{Type: "identity"}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(msg.ID, "", "backup service unavailable")
		return
	}
	result := s.backupServices.RollbackRestore(adminproto.RollbackRestoreRequest{
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
	if s.requireRecoveryAdminRuntime(requestID) == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionIdentityRestore, auth.Resource{Type: "identity"}) {
		return
	}
	if s.backupServices == nil {
		_ = s.SendError(requestID, "", "backup service unavailable")
		return
	}
	_ = s.WriteJSON(ProtocolReconcileStoreResultMessage(requestID, s.backupServices.ReconcileStore()))
}

func (s *Session) HandleListKeys(requestID string) {
	if s.requireUnlockedRuntime(requestID) == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionKeysView, auth.Resource{Type: "keys"}) {
		return
	}

	keys, err := s.keyServices.ListKeys()
	if err != nil {
		_ = s.SendError(requestID, "", err.Error())
		return
	}

	_ = s.WriteJSON(ProtocolKeysListMessage(requestID, keys))
}

func (s *Session) HandleGetKeyDetails(msg *protocol.GetKeyDetailsMessage) {
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionKeysView, auth.Resource{Type: "key", ID: msg.Address}) {
		return
	}

	details := s.keyServices.GetKeyDetails(adminproto.GetKeyDetailsRequest{Address: msg.Address})
	_ = s.WriteJSON(ProtocolKeyDetailsMessage(msg.ID, details))
}

func (s *Session) HandleListLibraryTemplates(requestID string) {
	if s.requireUnlockedRuntime(requestID) == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionTemplatesView, auth.Resource{Type: "templates"}) {
		return
	}
	result := s.templateServices.ListLibraryTemplates()
	_ = s.WriteJSON(ProtocolLibraryTemplatesMessage(requestID, result))
}

func (s *Session) HandleInstallLibraryTemplate(msg *protocol.InstallLibraryTemplateMessage) {
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionTemplatesInstall, auth.Resource{Type: "template", ID: msg.KeyType}) {
		return
	}
	result := s.templateServices.InstallLibraryTemplate(adminproto.InstallLibraryTemplateRequest{
		KeyType:      msg.KeyType,
		TemplateType: msg.TemplateType,
	})
	_ = s.WriteJSON(ProtocolInstallLibraryTemplateResultMessage(msg.ID, result))
}

func (s *Session) HandleListInstalledTemplates(requestID string) {
	if s.requireUnlockedRuntime(requestID) == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionTemplatesView, auth.Resource{Type: "templates"}) {
		return
	}
	result := s.templateServices.ListInstalledTemplates()
	_ = s.WriteJSON(ProtocolInstalledTemplatesMessage(requestID, result))
}

func (s *Session) HandleShowInstalledTemplate(msg *protocol.ShowInstalledTemplateMessage) {
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionTemplatesView, auth.Resource{Type: "template", ID: msg.KeyType}) {
		return
	}
	result := s.templateServices.ShowInstalledTemplate(adminproto.ShowInstalledTemplateRequest{
		KeyType: msg.KeyType,
	})
	_ = s.WriteJSON(ProtocolShowInstalledTemplateResultMessage(msg.ID, result))
}

func (s *Session) HandleShowLibraryTemplate(msg *protocol.ShowLibraryTemplateMessage) {
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionTemplatesView, auth.Resource{Type: "template", ID: msg.KeyType}) {
		return
	}
	result := s.templateServices.ShowLibraryTemplate(adminproto.ShowLibraryTemplateRequest{
		KeyType:      msg.KeyType,
		TemplateType: msg.TemplateType,
	})
	_ = s.WriteJSON(ProtocolShowLibraryTemplateResultMessage(msg.ID, result))
}

func (s *Session) HandleImportInstalledTemplate(msg *protocol.ImportInstalledTemplateMessage) {
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionTemplatesInstall, auth.Resource{Type: "template"}) {
		return
	}
	result := s.templateServices.ImportInstalledTemplate(adminproto.ImportInstalledTemplateRequest{
		TemplateYAML: []byte(msg.TemplateYAML),
	})
	_ = s.WriteJSON(ProtocolImportInstalledTemplateResultMessage(msg.ID, result))
}

func (s *Session) HandleRemoveInstalledTemplate(msg *protocol.RemoveInstalledTemplateMessage) {
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionTemplatesRemove, auth.Resource{Type: "template", ID: msg.KeyType}) {
		return
	}
	result := s.templateServices.RemoveInstalledTemplate(adminproto.RemoveInstalledTemplateRequest{
		KeyType: msg.KeyType,
	})
	_ = s.WriteJSON(ProtocolRemoveInstalledTemplateResultMessage(msg.ID, result))
}

func (s *Session) HandleActivateKeyType(msg *protocol.ActivateKeyTypeMessage) {
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionKeyTypesActivate, auth.Resource{Type: "keytype", ID: msg.KeyType}) {
		return
	}
	result := s.templateServices.ActivateKeyType(adminproto.ActivateKeyTypeRequest{
		KeyType: msg.KeyType,
	})
	_ = s.WriteJSON(ProtocolActivateKeyTypeResultMessage(msg.ID, result))
}

func (s *Session) HandleDeactivateKeyType(msg *protocol.DeactivateKeyTypeMessage) {
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionKeyTypesDeactivate, auth.Resource{Type: "keytype", ID: msg.KeyType}) {
		return
	}
	result := s.templateServices.DeactivateKeyType(adminproto.DeactivateKeyTypeRequest{
		KeyType: msg.KeyType,
	})
	_ = s.WriteJSON(ProtocolDeactivateKeyTypeResultMessage(msg.ID, result))
}

func (s *Session) HandleListKeyTypes(requestID string) {
	if s.requireBoundRuntime(requestID) == nil {
		return
	}
	if !s.authorize(requestID, auth.ActionKeyTypesView, auth.Resource{Type: "keytypes"}) {
		return
	}
	result := s.templateServices.ListKeyTypes()
	_ = s.WriteJSON(ProtocolKeyTypesMessage(requestID, result))
}

func (s *Session) HandleSignResponse(msg *protocol.SignResponseMessage) {
	if ir := s.BoundRuntime(); ir != nil {
		if !s.authorize(msg.ID, auth.ActionSignApprove, auth.Resource{Type: "sign_request", ID: msg.ID}) {
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
		if !s.authorize(msg.ID, auth.ActionTokenProvision, auth.Resource{Type: "token_provisioning", ID: msg.ID}) {
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
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	resource := auth.Resource{Type: "key"}
	if !s.authorize(msg.ID, auth.ActionKeysGenerate, resource) {
		return
	}
	gen := s.keyServices.GenerateKey(s.Context(), adminproto.GenerateKeyRequest{
		KeyType:    msg.KeyType,
		Name:       msg.Name,
		Parameters: msg.Parameters,
	})
	_ = s.WriteJSON(ProtocolGenerateResultMessage(msg.ID, gen))
}

func (s *Session) HandleDeleteKey(msg *protocol.DeleteKeyMessage) {
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	if !s.authorize(msg.ID, auth.ActionKeysDelete, auth.Resource{Type: "key", ID: msg.Address}) {
		return
	}
	del := s.keyServices.DeleteKey(adminproto.DeleteKeyRequest{Address: msg.Address})
	_ = s.WriteJSON(ProtocolDeleteResultMessage(msg.ID, del))
}

func (s *Session) HandleExportKey(msg *protocol.ExportKeyMessage) {
	msg.Passphrase.Zero()
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	resource := auth.Resource{Type: "key", ID: msg.Address}
	if !s.authorize(msg.ID, auth.ActionKeysExport, resource) {
		return
	}
	const reason = "key export is disabled; use encrypted backups for recovery"
	s.logAuthorizationDenied(s.Identity(), auth.ActionKeysExport, resource, reason)
	_ = s.SendError(msg.ID, protocol.ErrCodeAuthorizationDenied, reason)
}

func (s *Session) HandleImportKey(msg *protocol.ImportKeyMessage) {
	if s.requireUnlockedRuntime(msg.ID) == nil {
		return
	}
	resource := auth.Resource{Type: "key"}
	if !s.authorize(msg.ID, auth.ActionKeysImport, resource) {
		return
	}
	if !s.requireLocalImportTransport(msg.ID, auth.ActionKeysImport, resource) {
		return
	}
	imp := s.keyServices.ImportKey(adminproto.ImportKeyRequest{
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
