// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"encoding/json"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// Dispatch handles the subset of protocol messages that already live entirely
// within the transport-neutral admin protocol/session layer.
func (s *Session) Dispatch(raw []byte) bool {
	base, err := protocol.ParseAdminBaseMessage(raw)
	if err != nil {
		_ = s.SendError("", protocol.ErrCodeInvalidMessageFormat, "invalid message format")
		return true
	}
	sendInvalidRequest := func(message string) {
		_ = s.SendError(base.ID, protocol.ErrCodeInvalidRequest, message)
	}
	if base.Kind != protocol.MessageKindRequest {
		sendInvalidRequest("expected request message")
		return true
	}

	switch base.Type {
	case protocol.MsgTypeUnlock:
		var msg protocol.UnlockMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid unlock message")
			return true
		}
		s.HandleUnlock(&msg)
		return true
	case protocol.MsgTypeAdminActivity:
		var msg protocol.AdminActivityMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid admin activity message")
			return true
		}
		s.HandleAdminActivity(&msg)
		return true
	case protocol.MsgTypeLockIdentity:
		var msg protocol.LockIdentityMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid lock identity message")
			return true
		}
		s.HandleLockIdentity(&msg)
		return true
	case protocol.MsgTypeBackup:
		var msg protocol.BackupMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid backup message")
			return true
		}
		s.HandleBackup(&msg)
		return true
	case protocol.MsgTypeListBackups:
		var msg protocol.ListBackupsMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid list backups message")
			return true
		}
		s.HandleListBackups(msg.ID)
		return true
	case protocol.MsgTypeDeleteBackup:
		var msg protocol.DeleteBackupMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid delete backup message")
			return true
		}
		s.HandleDeleteBackup(&msg)
		return true
	case protocol.MsgTypeChangeStorePass:
		var msg protocol.ChangeStorePassphraseMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid change store passphrase message")
			return true
		}
		s.HandleChangeStorePassphrase(&msg)
		return true
	case protocol.MsgTypePreviewRestore:
		var msg protocol.PreviewRestoreMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid preview restore message")
			return true
		}
		s.HandlePreviewRestore(&msg)
		return true
	case protocol.MsgTypeRestoreBackup:
		var msg protocol.RestoreBackupMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid restore backup message")
			return true
		}
		s.HandleRestoreBackup(&msg)
		return true
	case protocol.MsgTypeRevokeToken:
		var msg protocol.RevokeTokenMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid revoke token message")
			return true
		}
		s.HandleRevokeToken(&msg)
		return true
	case protocol.MsgTypeGetAdminSettings:
		var msg protocol.GetAdminSettingsMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid get admin settings message")
			return true
		}
		s.HandleGetAdminSettings(msg.ID)
		return true
	case protocol.MsgTypeUpdateAdminSetting:
		var msg protocol.UpdateAdminSettingMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid update admin setting message")
			return true
		}
		s.HandleUpdateAdminSetting(&msg)
		return true
	case protocol.MsgTypeGetPolicySettings:
		var msg protocol.GetPolicySettingsMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid get policy settings message")
			return true
		}
		s.HandleGetPolicySettings(msg.ID)
		return true
	case protocol.MsgTypeGetPolicySnapshot:
		var msg protocol.GetPolicySnapshotMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid get policy snapshot message")
			return true
		}
		s.HandleGetPolicySnapshot(&msg)
		return true
	case protocol.MsgTypeReplacePolicy:
		var msg protocol.ReplacePolicyMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid replace policy message")
			return true
		}
		s.HandleReplacePolicy(&msg)
		return true
	case protocol.MsgTypeUpdatePolicySetting:
		var msg protocol.UpdatePolicySettingMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid update policy setting message")
			return true
		}
		s.HandleUpdatePolicySetting(&msg)
		return true
	case protocol.MsgTypeUpdatePolicyASAAmounts:
		var msg protocol.UpdatePolicyASAAmountsMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid update policy asa amounts message")
			return true
		}
		s.HandleUpdatePolicyASAAmounts(&msg)
		return true
	case protocol.MsgTypeSearchASAMetadata:
		var msg protocol.SearchASAMetadataMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid search asa metadata message")
			return true
		}
		s.HandleSearchASAMetadata(&msg)
		return true
	case protocol.MsgTypeResolveASAMetadata:
		var msg protocol.ResolveASAMetadataMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid resolve asa metadata message")
			return true
		}
		s.HandleResolveASAMetadata(&msg)
		return true
	case protocol.MsgTypeListKeys:
		var msg protocol.ListKeysMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid list keys message")
			return true
		}
		s.HandleListKeys(msg.ID)
		return true
	case protocol.MsgTypeGetKeyDetails:
		var msg protocol.GetKeyDetailsMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid get key details message")
			return true
		}
		s.HandleGetKeyDetails(&msg)
		return true
	case protocol.MsgTypeListLibraryTemplates:
		var msg protocol.ListLibraryTemplatesMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid list library templates message")
			return true
		}
		s.HandleListLibraryTemplates(msg.ID)
		return true
	case protocol.MsgTypeInstallLibraryTemplate:
		var msg protocol.InstallLibraryTemplateMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid install library template message")
			return true
		}
		s.HandleInstallLibraryTemplate(&msg)
		return true
	case protocol.MsgTypeListInstalledTemplates:
		var msg protocol.ListInstalledTemplatesMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid list installed templates message")
			return true
		}
		s.HandleListInstalledTemplates(msg.ID)
		return true
	case protocol.MsgTypeShowInstalledTemplate:
		var msg protocol.ShowInstalledTemplateMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid show installed template message")
			return true
		}
		s.HandleShowInstalledTemplate(&msg)
		return true
	case protocol.MsgTypeShowLibraryTemplate:
		var msg protocol.ShowLibraryTemplateMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid show library template message")
			return true
		}
		s.HandleShowLibraryTemplate(&msg)
		return true
	case protocol.MsgTypeImportInstalledTemplate:
		var msg protocol.ImportInstalledTemplateMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid import installed template message")
			return true
		}
		s.HandleImportInstalledTemplate(&msg)
		return true
	case protocol.MsgTypeRemoveInstalledTemplate:
		var msg protocol.RemoveInstalledTemplateMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid remove installed template message")
			return true
		}
		s.HandleRemoveInstalledTemplate(&msg)
		return true
	case protocol.MsgTypeActivateKeyType:
		var msg protocol.ActivateKeyTypeMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid activate key type message")
			return true
		}
		s.HandleActivateKeyType(&msg)
		return true
	case protocol.MsgTypeDeactivateKeyType:
		var msg protocol.DeactivateKeyTypeMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid deactivate key type message")
			return true
		}
		s.HandleDeactivateKeyType(&msg)
		return true
	case protocol.MsgTypeListKeyTypes:
		var msg protocol.ListKeyTypesMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid list key types message")
			return true
		}
		s.HandleListKeyTypes(msg.ID)
		return true
	case protocol.MsgTypeGenerateKey:
		var msg protocol.GenerateKeyMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid generate key message")
			return true
		}
		s.HandleGenerateKey(&msg)
		return true
	case protocol.MsgTypeDeleteKey:
		var msg protocol.DeleteKeyMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid delete key message")
			return true
		}
		s.HandleDeleteKey(&msg)
		return true
	case protocol.MsgTypeExportKey:
		var msg protocol.ExportKeyMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid export key message")
			return true
		}
		s.HandleExportKey(&msg)
		return true
	case protocol.MsgTypeImportKey:
		var msg protocol.ImportKeyMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid import key message")
			return true
		}
		s.HandleImportKey(&msg)
		return true
	case protocol.MsgTypeSignResponse:
		var msg protocol.SignResponseMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid sign response message")
			return true
		}
		s.HandleSignResponse(&msg)
		return true
	case protocol.MsgTypeTokenProvisioningResponse:
		var msg protocol.TokenProvisioningResponseMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			sendInvalidRequest("invalid token provisioning response message")
			return true
		}
		s.HandleTokenProvisioningResponse(&msg)
		return true
	default:
		return false
	}
}
