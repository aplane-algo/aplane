// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"fmt"

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
	request := UpdateAdminSettingRequest{Key: msg.Key, Value: msg.Value}
	err := s.settingsServices.UpdateAdminSetting(ir, request)
	_ = s.WriteJSON(ProtocolUpdateAdminSettingResultMessage(msg.ID, request, err))
}

func (s *Session) HandleGetPolicySettings(requestID string) {
	ir := s.productOrBoundRuntime()
	if !s.authorize(requestID, auth.ActionPolicyView, auth.Resource{Type: "policy", IdentityID: ir.ID()}) {
		return
	}
	settings := s.settingsServices.BuildPolicySettings(ir)
	_ = s.WriteJSON(ProtocolPolicySettingsMessage(requestID, settings))
}

func (s *Session) HandleGetPolicySnapshot(msg *protocol.GetPolicySnapshotMessage) {
	ir := s.productOrBoundRuntime()
	if !s.authorize(msg.ID, auth.ActionPolicyView, auth.Resource{Type: "policy", IdentityID: ir.ID()}) {
		return
	}
	snapshot := s.settingsServices.BuildPolicySnapshot(ir, NormalizePolicyTarget(msg.Target))
	_ = s.WriteJSON(ProtocolPolicySnapshotMessage(msg.ID, snapshot))
}

func (s *Session) HandleReplacePolicy(msg *protocol.ReplacePolicyMessage) {
	ir := s.productOrBoundRuntime()
	if !s.authorize(msg.ID, auth.ActionPolicyUpdate, auth.Resource{Type: "policy", IdentityID: ir.ID()}) {
		return
	}
	result := s.settingsServices.ReplacePolicy(ir, ReplacePolicyRequest{
		Target:                NormalizePolicyTarget(msg.Target),
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
	result := s.settingsServices.ValidatePolicy(ir, ValidatePolicyRequest{
		Target:     NormalizePolicyTarget(msg.Target),
		PolicyYAML: msg.PolicyYAML,
	})
	_ = s.WriteJSON(ProtocolValidatePolicyResultMessage(msg.ID, result))
}

func (s *Session) HandleUpdatePolicySetting(msg *protocol.UpdatePolicySettingMessage) {
	ir := s.productOrBoundRuntime()
	if !s.authorize(msg.ID, auth.ActionPolicyUpdate, auth.Resource{Type: "policy", IdentityID: ir.ID()}) {
		return
	}
	request := UpdatePolicySettingRequest{Key: msg.Key, Value: msg.Value}
	err := s.settingsServices.UpdatePolicySetting(ir, request)
	_ = s.WriteJSON(ProtocolUpdatePolicySettingResultMessage(msg.ID, request, err))
}

func (s *Session) HandleUpdatePolicyASAAmounts(msg *protocol.UpdatePolicyASAAmountsMessage) {
	ir := s.productOrBoundRuntime()
	if !s.authorize(msg.ID, auth.ActionPolicyUpdate, auth.Resource{Type: "policy", IdentityID: ir.ID()}) {
		return
	}
	err := s.settingsServices.UpdatePolicyASAAmounts(ir, UpdatePolicyASAAmountsRequest{
		ReviewASAAmounts:   msg.ReviewASAAmounts,
		MaxASAAmounts:      msg.MaxASAAmounts,
		ReviewAlgoPayments: msg.ReviewAlgoPayments,
		MaxAlgoPayments:    msg.MaxAlgoPayments,
		Mainnet:            msg.Mainnet,
		Testnet:            msg.Testnet,
		Betanet:            msg.Betanet,
	})

	_ = s.WriteJSON(ProtocolUpdatePolicyASAAmountsResultMessage(msg.ID, err))
}

func (s *Session) HandleSearchASAMetadata(msg *protocol.SearchASAMetadataMessage) {
	ir := s.productOrBoundRuntime()
	if !s.authorize(msg.ID, auth.ActionPolicyView, auth.Resource{Type: "policy", IdentityID: ir.ID()}) {
		return
	}
	result := s.settingsServices.SearchASAMetadata(ir, SearchASAMetadataRequest{
		Network: msg.Network,
		Query:   msg.Query,
	})
	out := ProtocolASAMetadataResultsMessage(result)
	out.ID = msg.ID
	_ = s.WriteJSON(out)
}

func (s *Session) HandleResolveASAMetadata(msg *protocol.ResolveASAMetadataMessage) {
	ir := s.productOrBoundRuntime()
	if !s.authorize(msg.ID, auth.ActionPolicyUpdate, auth.Resource{Type: "policy", IdentityID: ir.ID()}) {
		return
	}
	result := s.settingsServices.ResolveASAMetadata(ir, ResolveASAMetadataRequest{
		Network: msg.Network,
		AssetID: msg.AssetID,
	})
	out := ProtocolASAMetadataResultMessage(result)
	out.ID = msg.ID
	_ = s.WriteJSON(out)
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

	success, keyCount, errStr := s.identityServices.UnlockIdentity(ir, passphraseBytes)
	_ = s.WriteJSON(ProtocolUnlockResultMessage(msg.ID, success, keyCount, errStr))
}

func (s *Session) HandleLockIdentity(msg *protocol.LockIdentityMessage) {
	if s.State() != StateAuthenticated {
		_ = s.WriteJSON(ProtocolLockIdentityResultMessage(
			msg.ID,
			fmt.Errorf("no identity bound to session"),
		))
		return
	}
	ir := s.BoundRuntime()
	if ir == nil {
		_ = s.WriteJSON(ProtocolLockIdentityResultMessage(
			msg.ID,
			fmt.Errorf("no identity bound to session"),
		))
		return
	}

	resource := auth.Resource{Type: "identity", ID: ir.ID(), IdentityID: ir.ID()}
	identity := s.Identity()
	if s.authorizer != nil && identity == nil {
		_ = s.WriteJSON(ProtocolLockIdentityResultMessage(
			msg.ID,
			fmt.Errorf("no identity bound to session"),
		))
		return
	}
	if err := s.authorizeIdentity(identity, auth.ActionIdentityLock, resource); err != nil {
		s.logAuthorizationDenied(identity, auth.ActionIdentityLock, resource, err.Error())
		_ = s.WriteJSON(ProtocolLockIdentityResultMessage(
			msg.ID,
			fmt.Errorf("authorization denied"),
		))
		return
	}

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
	result := s.backupServices.BackupIdentity(ir, BackupIdentityRequest{
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
	ir := s.requireUnlockedRuntime(requestID)
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
	result := s.backupServices.DeleteBackup(ir, DeleteBackupRequest{ArchivePath: msg.ArchivePath})
	_ = s.WriteJSON(ProtocolDeleteBackupResultMessage(msg.ID, result))
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
	result := s.identityServices.ChangeStorePassphrase(ir, ChangeStorePassphraseRequest{
		CurrentPassphrase: currentPassphrase,
		NewPassphrase:     newPassphrase,
	})
	_ = s.WriteJSON(ProtocolChangeStorePassphraseResultMessage(msg.ID, result))
}

func (s *Session) HandlePreviewRestore(msg *protocol.PreviewRestoreMessage) {
	ir := s.requireUnlockedRuntime(msg.ID)
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
	result := s.backupServices.PreviewRestore(ir, PreviewRestoreRequest{
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
	ir := s.requireUnlockedRuntime(msg.ID)
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
	if audit, ok := s.audit.(interface {
		LogBackupRestoreStartedContext(SessionContext, string, int)
	}); ok {
		audit.LogBackupRestoreStartedContext(s.SessionContext(), msg.ArchivePath, len(msg.Addresses))
	}
	exportPassphrase := msg.ExportPassphrase.Clone()
	defer zeroBytes(exportPassphrase)
	defer msg.ExportPassphrase.Zero()
	result := s.backupServices.RestoreBackup(ir, RestoreBackupRequest{
		ArchivePath:      msg.ArchivePath,
		Addresses:        append([]string(nil), msg.Addresses...),
		Overwrite:        msg.Overwrite,
		ExportPassphrase: exportPassphrase,
	})
	if audit, ok := s.audit.(interface {
		LogBackupRestoreCompletedContext(SessionContext, string, int)
		LogBackupRestorePartialContext(SessionContext, string, int, int)
		LogBackupRestoreFailedContext(SessionContext, string)
	}); ok {
		switch {
		case result.Success:
			audit.LogBackupRestoreCompletedContext(s.SessionContext(), result.ArchivePath, len(result.Restored))
		case len(result.Restored) > 0:
			audit.LogBackupRestorePartialContext(s.SessionContext(), result.ArchivePath, len(result.Restored), len(result.Errors))
		case result.Error != "":
			audit.LogBackupRestoreFailedContext(s.SessionContext(), result.Error)
		}
	}
	_ = s.WriteJSON(ProtocolRestoreBackupResultMessage(msg.ID, result))
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

	details := s.keyServices.GetKeyDetails(ir, GetKeyDetailsRequest{Address: msg.Address})
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
	result := s.templateServices.InstallLibraryTemplate(ir, InstallLibraryTemplateRequest{
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
	result := s.templateServices.ShowInstalledTemplate(ir, ShowInstalledTemplateRequest{
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
	result := s.templateServices.ShowLibraryTemplate(ir, ShowLibraryTemplateRequest{
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
	result := s.templateServices.ImportInstalledTemplate(ir, ImportInstalledTemplateRequest{
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
	result := s.templateServices.RemoveInstalledTemplate(ir, RemoveInstalledTemplateRequest{
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
	result := s.templateServices.ActivateKeyType(ir, ActivateKeyTypeRequest{
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
	result := s.templateServices.DeactivateKeyType(ir, DeactivateKeyTypeRequest{
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
	gen := s.keyServices.GenerateKey(s.Context(), ir, GenerateKeyRequest{
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
	del := s.keyServices.DeleteKey(ir, DeleteKeyRequest{Address: msg.Address})
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
	imp := s.keyServices.ImportKey(ir, ImportKeyRequest{
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
