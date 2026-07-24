// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"maps"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapi"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

func ProtocolStatusMessage(state string, keyCount int) protocol.StatusMessage {
	return protocol.StatusMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeStatus},
		State:       state,
		KeyCount:    keyCount,
	}
}

func ProtocolErrorMessage(requestID, code, errMsg string) protocol.ErrorMessage {
	if code == "" {
		code = protocol.IPCErrorCode(errMsg)
	}
	return protocol.ErrorMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeError,
			ID:   requestID,
		},
		Code:  code,
		Error: errMsg,
	}
}

func ProtocolAuthResultMessage(success bool, code, errMsg string) protocol.AuthResultMessage {
	return protocol.AuthResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAuthResult},
		Success:     success,
		Code:        code,
		Error:       errMsg,
	}
}

func ProtocolRevokeTokenResultMessage(id string, err error) protocol.RevokeTokenResultMessage {
	result := protocol.RevokeTokenResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRevokeTokenResult,
			ID:   id,
		},
		Success: err == nil,
	}
	if err != nil {
		result.Code = protocol.CodeForError(err)
		result.Error = err.Error()
	}
	return result
}

func ProtocolUpdateAdminSettingResultMessage(id string, request adminproto.UpdateAdminSettingRequest, err error) protocol.UpdateAdminSettingResultMessage {
	result := protocol.UpdateAdminSettingResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeUpdateAdminSettingResult,
			ID:   id,
		},
		Success: err == nil,
		Key:     request.Key,
		Value:   request.Value,
	}
	if err != nil {
		result.Code = protocol.CodeForError(err)
		result.Error = err.Error()
	}
	return result
}

func ProtocolUnlockResultMessage(id string, success bool, keyCount int, errMsg string, code string) protocol.UnlockResultMessage {
	if code == "" && errMsg != "" {
		code = protocol.IPCErrorCode(errMsg)
	}
	return protocol.UnlockResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeUnlockResult,
			ID:   id,
		},
		Success:  success,
		KeyCount: keyCount,
		Code:     code,
		Error:    errMsg,
	}
}

func ProtocolLockIdentityResultMessage(id string, err error) protocol.LockIdentityResultMessage {
	result := protocol.LockIdentityResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeLockIdentityResult,
			ID:   id,
		},
		Success: err == nil,
	}
	if err != nil {
		result.Code = protocol.CodeForError(err)
		result.Error = err.Error()
	}
	return result
}

func ProtocolBackupResultMessage(id string, result adminproto.BackupIdentityResult) protocol.BackupResultMessage {
	return protocol.BackupResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeBackupResult,
			ID:   id,
		},
		Success:         result.Success,
		ArchivePath:     result.ArchivePath,
		ArchiveChecksum: result.ArchiveChecksum,
		ArchiveSize:     result.ArchiveSize,
		KeyCount:        result.KeyCount,
		Addresses:       append([]string(nil), result.Addresses...),
		Verified:        result.Verified,
		SkippedKeys:     maps.Clone(result.SkippedKeys),
		Code:            result.Code,
		Error:           result.Error,
	}
}

func ProtocolBackupsListMessage(id string, result adminproto.ListBackupsResult) protocol.BackupsListMessage {
	return protocol.BackupsListMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeBackupsList,
			ID:   id,
		},
		Backups: protocolBackupInfos(result.Backups),
		Code:    result.Code,
		Error:   result.Error,
	}
}

func ProtocolDeleteBackupResultMessage(id string, result adminproto.DeleteBackupResult) protocol.DeleteBackupResultMessage {
	return protocol.DeleteBackupResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeDeleteBackupResult,
			ID:   id,
		},
		Success: result.Success,
		Code:    result.Code,
		Error:   result.Error,
	}
}

func ProtocolInitializeStoreResultMessage(id string, result adminproto.InitializeStoreResult) protocol.InitializeStoreResultMessage {
	return protocol.InitializeStoreResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeInitializeStoreResult,
			ID:   id,
		},
		Success:       result.Success,
		MetadataDir:   result.MetadataDir,
		HelperWarning: result.HelperWarning,
		Code:          result.Code,
		Error:         result.Error,
	}
}

func ProtocolChangeStorePassphraseResultMessage(id string, result adminproto.ChangeStorePassphraseResult) protocol.ChangeStorePassphraseResultMessage {
	return protocol.ChangeStorePassphraseResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeChangeStorePassResult,
			ID:   id,
		},
		Success:                  result.Success,
		KeysMigrated:             result.KeysMigrated,
		TemplatesMigrated:        result.TemplatesMigrated,
		RecoveredFilesMigrated:   result.RecoveredFilesMigrated,
		PolicySidecarsMigrated:   result.PolicySidecarsMigrated,
		NodeRoleSidecarsMigrated: result.NodeRoleSidecarsMigrated,
		Code:                     result.Code,
		Error:                    result.Error,
	}
}

func ProtocolRestorePreviewMessage(id string, result adminproto.RestorePreviewResult) protocol.RestorePreviewMessage {
	return protocol.RestorePreviewMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRestorePreview,
			ID:   id,
		},
		ArchivePath: result.ArchivePath,
		Keys:        protocolRestoreKeyInfos(result.Keys),
		Errors:      protocolRestoreErrors(result.Errors),
		Code:        result.Code,
		Error:       result.Error,
	}
}

func ProtocolRecoverBackupResultMessage(id string, result adminproto.RecoverBackupResult) protocol.RecoverBackupResultMessage {
	return protocol.RecoverBackupResultMessage{
		BaseMessage:     protocol.BaseMessage{Type: protocol.MsgTypeRecoverBackupResult, ID: id},
		Success:         result.Success,
		RestoreID:       result.RestoreID,
		ArchiveName:     result.ArchiveName,
		ArchiveChecksum: result.ArchiveChecksum,
		EntryCount:      result.EntryCount,
		Code:            result.Code,
		Error:           result.Error,
	}
}

func ProtocolRecoveredListMessage(id string, result adminproto.ListRecoveredResult) protocol.RecoveredListMessage {
	batches := make([]protocol.RecoveredBatchInfo, len(result.Batches))
	for i, batch := range result.Batches {
		batches[i] = protocol.RecoveredBatchInfo{
			RestoreID:          batch.RestoreID,
			CreatedAt:          batch.CreatedAt,
			ArchiveName:        batch.ArchiveName,
			ArchiveChecksum:    batch.ArchiveChecksum,
			SourceNodeRole:     batch.SourceNodeRole,
			SourcePolicyStatus: batch.SourcePolicyStatus,
			SourcePolicySHA256: batch.SourcePolicySHA256,
			EntryCount:         batch.EntryCount,
		}
	}
	return protocol.RecoveredListMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRecoveredList, ID: id},
		Batches:     batches,
		Code:        result.Code,
		Error:       result.Error,
	}
}

func ProtocolReviewRecoveredResultMessage(id string, result adminproto.ReviewRecoveredResult) protocol.ReviewRecoveredResultMessage {
	return protocol.ReviewRecoveredResultMessage{
		BaseMessage:                  protocol.BaseMessage{Type: protocol.MsgTypeReviewRecoveredResult, ID: id},
		Success:                      result.Success,
		RestoreID:                    result.RestoreID,
		State:                        result.State,
		ArchiveChecksum:              result.ArchiveChecksum,
		SourceNodeRole:               result.SourceNodeRole,
		SourcePolicyStatus:           result.SourcePolicyStatus,
		SourcePolicySHA256:           result.SourcePolicySHA256,
		DestinationPolicySHA256:      result.DestinationPolicySHA256,
		DestinationApprovalMode:      string(result.DestinationApprovalMode),
		UnattendedSigningWarning:     result.UnattendedSigningWarning,
		PolicyComparison:             result.PolicyComparison,
		SecurityChanges:              protocolRecoveryPolicyChanges(result.SecurityChanges),
		ChangedPaths:                 append([]string(nil), result.ChangedPaths...),
		UnknownSourceSettings:        append([]string(nil), result.UnknownSourceSettings...),
		Entries:                      protocolRecoveredReviewEntries(result.Entries),
		ActiveConflicts:              protocolRecoveredActiveConflicts(result.ActiveConflicts),
		ReviewToken:                  result.ReviewToken,
		AcknowledgePolicyTransition:  result.AcknowledgePolicyTransition,
		AcknowledgeUnattendedSigning: result.AcknowledgeUnattendedSigning,
		ReplaceExisting:              result.ReplaceExisting,
		Code:                         result.Code,
		Error:                        result.Error,
	}
}

func ProtocolActivateRecoveredResultMessage(id string, result adminproto.ActivateRecoveredResult) protocol.ActivateRecoveredResultMessage {
	return protocol.ActivateRecoveredResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeActivateRecoveredResult, ID: id},
		Success:     result.Success,
		RestoreID:   result.RestoreID,
		Activated:   protocolRecoveredReviewEntries(result.Activated),
		KeyCount:    result.KeyCount,
		Code:        result.Code,
		Error:       result.Error,
	}
}

func ProtocolRollbackRecoveredResultMessage(id string, result adminproto.RollbackRecoveredResult) protocol.RollbackRecoveredResultMessage {
	return protocol.RollbackRecoveredResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRollbackRecoveredResult, ID: id},
		Success:     result.Success,
		RestoreID:   result.RestoreID,
		KeyCount:    result.KeyCount,
		Code:        result.Code,
		Error:       result.Error,
	}
}

func ProtocolPurgeRecoveredResultMessage(id string, result adminproto.PurgeRecoveredResult) protocol.PurgeRecoveredResultMessage {
	return protocol.PurgeRecoveredResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePurgeRecoveredResult, ID: id},
		Success:     result.Success,
		RestoreID:   result.RestoreID,
		Code:        result.Code,
		Error:       result.Error,
	}
}

func protocolRecoveredReviewEntries(items []adminproto.RecoveredReviewEntry) []protocol.RecoveredReviewEntry {
	out := make([]protocol.RecoveredReviewEntry, len(items))
	for i, item := range items {
		out[i] = protocol.RecoveredReviewEntry{
			Selector: item.Selector,
			Category: item.Category,
			KeyType:  item.KeyType,
		}
	}
	return out
}

func protocolRecoveredActiveConflicts(items []adminproto.RecoveredActiveConflict) []protocol.RecoveredActiveConflict {
	out := make([]protocol.RecoveredActiveConflict, len(items))
	for i, item := range items {
		out[i] = protocol.RecoveredActiveConflict{
			Selector: item.Selector,
			Category: item.Category,
			KeyType:  item.KeyType,
			SHA256:   item.SHA256,
		}
	}
	return out
}

func protocolRecoveryPolicyChanges(items []adminproto.RecoveryPolicyChange) []protocol.RecoveryPolicyChange {
	out := make([]protocol.RecoveryPolicyChange, len(items))
	for i, item := range items {
		out[i] = protocol.RecoveryPolicyChange{
			Category:    item.Category,
			Selector:    item.Selector,
			Path:        item.Path,
			Source:      item.Source,
			Destination: item.Destination,
		}
	}
	return out
}

func ProtocolKeysListMessage(id string, keys []adminproto.KeyInfo) protocol.KeysListMessage {
	return protocol.KeysListMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeKeysList,
			ID:   id,
		},
		Keys: ProtocolKeyInfos(keys),
	}
}

func protocolBackupInfos(items []adminproto.BackupInfo) []protocol.BackupInfo {
	if len(items) == 0 {
		return nil
	}
	out := make([]protocol.BackupInfo, len(items))
	for i, item := range items {
		out[i] = protocol.BackupInfo{
			Path:      item.Path,
			FileName:  item.FileName,
			CreatedAt: item.CreatedAt,
			Size:      item.Size,
			Checksum:  item.Checksum,
			Verified:  item.Verified,
		}
	}
	return out
}

func protocolRestoreKeyInfos(items []adminproto.RestoreKeyInfo) []protocol.RestoreKeyInfo {
	if len(items) == 0 {
		return nil
	}
	out := make([]protocol.RestoreKeyInfo, len(items))
	for i, item := range items {
		out[i] = protocol.RestoreKeyInfo{
			Address:       item.Address,
			KeyType:       item.KeyType,
			AlreadyExists: item.AlreadyExists,
			HasTemplate:   item.HasTemplate,
			TemplateType:  item.TemplateType,
			Error:         item.Error,
		}
	}
	return out
}

func protocolRestoreErrors(items []adminproto.RestoreError) []protocol.RestoreError {
	if len(items) == 0 {
		return nil
	}
	out := make([]protocol.RestoreError, len(items))
	for i, item := range items {
		out[i] = protocol.RestoreError{
			Address: item.Address,
			Error:   item.Error,
		}
	}
	return out
}

func ProtocolAdminSettingsMessage(requestID string, settings adminproto.AdminSettings) protocol.AdminSettingsMessage {
	return protocol.AdminSettingsMessage{
		BaseMessage:          protocol.BaseMessage{Type: protocol.MsgTypeAdminSettings, ID: requestID},
		UserAutoApprove:      settings.UserAutoApprove,
		LockOnDisconnect:     settings.LockOnDisconnect,
		PassphraseTimeout:    settings.PassphraseTimeout,
		PassphraseMethod:     settings.PassphraseMethod,
		NodeRole:             settings.NodeRole,
		SSHEnabled:           settings.SSHEnabled,
		SSHListenAddress:     settings.SSHListenAddress,
		SSHPort:              settings.SSHPort,
		SSHFingerprint:       settings.SSHFingerprint,
		SSHClients:           settings.SSHClients,
		SignerPort:           settings.SignerPort,
		TEALCompileNet:       settings.TEALCompileNet,
		EndpointAdvertiseURL: settings.EndpointAdvertiseURL,
		EndpointDisplayURL:   settings.EndpointDisplayURL,
		Theme:                settings.Theme,
	}
}

func ProtocolPolicySnapshotMessage(id string, snapshot adminproto.PolicySnapshot) protocol.PolicySnapshotMessage {
	return protocol.PolicySnapshotMessage{
		BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypePolicySnapshot, ID: id},
		Success:      snapshot.Success,
		Target:       string(snapshot.Target),
		IdentityID:   snapshot.IdentityID,
		PolicyYAML:   snapshot.PolicyYAML,
		PolicySHA256: snapshot.PolicySHA256,
		Canonical:    snapshot.Canonical,
		Code:         snapshot.Code,
		Error:        snapshot.Error,
	}
}

func ProtocolReplacePolicyResultMessage(id string, snapshot adminproto.PolicySnapshot) protocol.ReplacePolicyResultMessage {
	return protocol.ReplacePolicyResultMessage{
		BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypeReplacePolicyResult, ID: id},
		Success:      snapshot.Success,
		Target:       string(snapshot.Target),
		IdentityID:   snapshot.IdentityID,
		PolicyYAML:   snapshot.PolicyYAML,
		PolicySHA256: snapshot.PolicySHA256,
		Canonical:    snapshot.Canonical,
		Code:         snapshot.Code,
		Error:        snapshot.Error,
	}
}

func ProtocolValidatePolicyResultMessage(id string, result adminproto.ValidatePolicyResult) protocol.ValidatePolicyResultMessage {
	return protocol.ValidatePolicyResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeValidatePolicyResult, ID: id},
		Success:     result.Success,
		Target:      string(result.Target),
		IdentityID:  result.IdentityID,
		Code:        result.Code,
		Error:       result.Error,
	}
}

func ProtocolGenerateResultMessage(id string, result adminproto.GenerateKeyResult) protocol.GenerateResultMessage {
	// Mnemonic and WordCount remain in the wire schema for client
	// compatibility but are never populated: recovery material does not cross
	// the admin-protocol boundary.
	return protocol.GenerateResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeGenerateResult,
			ID:   id,
		},
		Success:    result.Success,
		Address:    result.Address,
		KeyType:    result.KeyType,
		Parameters: result.Parameters,
		Code:       result.Code,
		Error:      result.Error,
	}
}

func ProtocolDeleteResultMessage(id string, result adminproto.DeleteKeyResult) protocol.DeleteResultMessage {
	return protocol.DeleteResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeDeleteResult,
			ID:   id,
		},
		Success: result.Success,
		Code:    result.Code,
		Error:   result.Error,
	}
}

func ProtocolImportResultMessage(id string, result adminproto.ImportKeyResult) protocol.ImportResultMessage {
	return protocol.ImportResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeImportResult,
			ID:   id,
		},
		Success: result.Success,
		Address: result.Address,
		KeyType: result.KeyType,
		Code:    result.Code,
		Error:   result.Error,
	}
}

func ProtocolKeyDetailsMessage(id string, result adminproto.GetKeyDetailsResult) protocol.KeyDetailsMessage {
	return protocol.KeyDetailsMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeKeyDetails,
			ID:   id,
		},
		Success:                  result.Success,
		Address:                  result.Address,
		KeyType:                  result.KeyType,
		PublicKeyHex:             result.PublicKeyHex,
		Parameters:               result.Parameters,
		DisplayTEAL:              result.DisplayTEAL,
		TemplateProvenanceStatus: result.TemplateProvenanceStatus,
		TemplateProvenanceNote:   result.TemplateProvenanceNote,
		Code:                     result.Code,
		Error:                    result.Error,
	}
}

func ProtocolLibraryTemplatesMessage(id string, result adminproto.ListLibraryTemplatesResult) protocol.LibraryTemplatesMessage {
	return protocol.LibraryTemplatesMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeLibraryTemplates,
			ID:   id,
		},
		Templates: protocolLibraryTemplates(result.Templates),
		Code:      result.Code,
		Error:     result.Error,
	}
}

func ProtocolInstallLibraryTemplateResultMessage(id string, result adminproto.InstallLibraryTemplateResult) protocol.InstallLibraryTemplateResultMessage {
	return protocol.InstallLibraryTemplateResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeInstallLibraryTemplateResult,
			ID:   id,
		},
		Success:       result.Success,
		KeyType:       result.KeyType,
		TemplateType:  result.TemplateType,
		AlreadyExists: result.AlreadyExists,
		Code:          result.Code,
		Error:         result.Error,
	}
}

func ProtocolInstalledTemplatesMessage(id string, result adminproto.ListInstalledTemplatesResult) protocol.InstalledTemplatesMessage {
	items := make([]protocol.InstalledTemplateInfo, 0, len(result.Templates))
	for _, item := range result.Templates {
		items = append(items, protocol.InstalledTemplateInfo{
			KeyType:      item.KeyType,
			TemplateType: item.TemplateType,
			Size:         item.Size,
			Enabled:      item.Enabled,
		})
	}
	return protocol.InstalledTemplatesMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeInstalledTemplates,
			ID:   id,
		},
		Templates: items,
		Code:      result.Code,
		Error:     result.Error,
	}
}

func ProtocolShowInstalledTemplateResultMessage(id string, result adminproto.ShowInstalledTemplateResult) protocol.ShowInstalledTemplateResultMessage {
	return protocol.ShowInstalledTemplateResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeShowInstalledTemplateResult,
			ID:   id,
		},
		Success:      result.Success,
		KeyType:      result.KeyType,
		TemplateType: result.TemplateType,
		TemplateYAML: protocol.SensitiveBytes(result.TemplateYAML),
		Code:         result.Code,
		Error:        result.Error,
	}
}

func ProtocolShowLibraryTemplateResultMessage(id string, result adminproto.ShowLibraryTemplateResult) protocol.ShowLibraryTemplateResultMessage {
	return protocol.ShowLibraryTemplateResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeShowLibraryTemplateResult,
			ID:   id,
		},
		Success:       result.Success,
		KeyType:       result.KeyType,
		TemplateType:  result.TemplateType,
		SourcePath:    result.SourcePath,
		SourceSHA256:  result.SourceSHA256,
		SourceModTime: result.SourceModTime,
		TemplateYAML:  protocol.SensitiveBytes(result.TemplateYAML),
		Code:          result.Code,
		Error:         result.Error,
	}
}

func ProtocolImportInstalledTemplateResultMessage(id string, result adminproto.ImportInstalledTemplateResult) protocol.ImportInstalledTemplateResultMessage {
	return protocol.ImportInstalledTemplateResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeImportInstalledTemplateResult,
			ID:   id,
		},
		Success:       result.Success,
		KeyType:       result.KeyType,
		TemplateType:  result.TemplateType,
		AlreadyExists: result.AlreadyExists,
		Code:          result.Code,
		Error:         result.Error,
	}
}

func ProtocolRemoveInstalledTemplateResultMessage(id string, result adminproto.RemoveInstalledTemplateResult) protocol.RemoveInstalledTemplateResultMessage {
	return protocol.RemoveInstalledTemplateResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRemoveInstalledTemplateResult,
			ID:   id,
		},
		Success:      result.Success,
		KeyType:      result.KeyType,
		TemplateType: result.TemplateType,
		Removed:      result.Removed,
		Code:         result.Code,
		Error:        result.Error,
	}
}

func ProtocolActivateKeyTypeResultMessage(id string, result adminproto.ActivateKeyTypeResult) protocol.ActivateKeyTypeResultMessage {
	return protocol.ActivateKeyTypeResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeActivateKeyTypeResult,
			ID:   id,
		},
		Success:       result.Success,
		KeyType:       result.KeyType,
		AlreadyExists: result.AlreadyExists,
		Code:          result.Code,
		Error:         result.Error,
	}
}

func ProtocolDeactivateKeyTypeResultMessage(id string, result adminproto.DeactivateKeyTypeResult) protocol.DeactivateKeyTypeResultMessage {
	return protocol.DeactivateKeyTypeResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeDeactivateKeyTypeResult,
			ID:   id,
		},
		Success: result.Success,
		KeyType: result.KeyType,
		Removed: result.Removed,
		Code:    result.Code,
		Error:   result.Error,
	}
}

func ProtocolKeyTypesMessage(id string, result adminproto.ListKeyTypesResult) protocol.KeyTypesMessage {
	return protocol.KeyTypesMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeKeyTypes,
			ID:   id,
		},
		KeyTypes: protocolKeyTypes(result.KeyTypes),
		Code:     result.Code,
		Error:    result.Error,
	}
}

func ProtocolKeyInfos(keys []adminproto.KeyInfo) []protocol.AdminKeyInfo {
	if len(keys) == 0 {
		return nil
	}
	out := make([]protocol.AdminKeyInfo, len(keys))
	for i, key := range keys {
		out[i] = protocol.AdminKeyInfo{
			Address:                  key.Address,
			KeyType:                  key.KeyType,
			Name:                     key.Name,
			TemplateProvenanceStatus: key.TemplateProvenanceStatus,
			TemplateProvenanceNote:   key.TemplateProvenanceNote,
		}
	}
	return out
}

func protocolLibraryTemplates(items []adminproto.LibraryTemplateInfo) []protocol.LibraryTemplateInfo {
	if len(items) == 0 {
		return nil
	}
	out := make([]protocol.LibraryTemplateInfo, len(items))
	for i, item := range items {
		out[i] = protocol.LibraryTemplateInfo{
			KeyType:      item.KeyType,
			TemplateType: item.TemplateType,
			DisplayName:  item.DisplayName,
			Description:  item.Description,
			SourcePath:   item.SourcePath,
			FileName:     item.FileName,
			Parameters:   protocolCreationParams(item.Parameters),
			RuntimeArgs:  protocolRuntimeArgs(item.RuntimeArgs),
			Installed:    item.Installed,
			Enabled:      item.Enabled,
			Conflict:     item.Conflict,
			Invalid:      item.Invalid,
		}
	}
	return out
}

func protocolKeyTypes(items []signerapi.KeyTypeInfo) []protocol.KeyTypeInfo {
	if len(items) == 0 {
		return nil
	}
	out := make([]protocol.KeyTypeInfo, len(items))
	for i, item := range items {
		out[i] = protocol.KeyTypeInfo{
			KeyType:           item.KeyType,
			Family:            item.Family,
			DisplayName:       item.DisplayName,
			Description:       item.Description,
			RequiresLogicSig:  item.RequiresLogicSig,
			MnemonicWordCount: item.MnemonicWordCount,
			MnemonicImport:    item.MnemonicImport,
			MnemonicScheme:    item.MnemonicScheme,
			CreationParams:    protocolCreationParams(item.CreationParams),
			RuntimeArgs:       protocolRuntimeArgs(item.RuntimeArgs),
		}
	}
	return out
}

func protocolCreationParams(params []signerapi.CreationParamInfo) []protocol.TemplateParamInfo {
	if len(params) == 0 {
		return nil
	}
	out := make([]protocol.TemplateParamInfo, len(params))
	for i, p := range params {
		out[i] = protocol.TemplateParamInfo{
			Name:        p.Name,
			Label:       p.Label,
			Description: p.Description,
			Type:        p.Type,
			Required:    p.Required,
			MaxLength:   p.MaxLength,
			InputModes:  protocolInputModes(p.InputModes),
			Options:     append([]string(nil), p.Options...),
			MinItems:    p.MinItems,
			MaxItems:    p.MaxItems,
			Example:     p.Example,
			Placeholder: p.Placeholder,
			Min:         p.Min,
			Max:         p.Max,
			Default:     p.Default,
		}
	}
	return out
}

func protocolInputModes(modes []signerapi.InputModeInfo) []protocol.InputModeInfo {
	if len(modes) == 0 {
		return nil
	}
	out := make([]protocol.InputModeInfo, len(modes))
	for i, mode := range modes {
		out[i] = protocol.InputModeInfo{
			Name:       mode.Name,
			Label:      mode.Label,
			Transform:  mode.Transform,
			ByteLength: mode.ByteLength,
			InputType:  mode.InputType,
		}
	}
	return out
}

func protocolRuntimeArgs(args []signerapi.RuntimeArgInfo) []protocol.TemplateArgInfo {
	if len(args) == 0 {
		return nil
	}
	out := make([]protocol.TemplateArgInfo, len(args))
	for i, a := range args {
		out[i] = protocol.TemplateArgInfo{
			Name:        a.Name,
			Label:       a.Label,
			Description: a.Description,
			Type:        a.Type,
			Required:    a.Required,
			ByteLength:  a.ByteLength,
			MaxSize:     a.MaxSize,
		}
	}
	return out
}

func ProtocolSignRequestMessage(req signerapproval.SignRequest) protocol.SignRequestMessage {
	return protocol.SignRequestMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeSignRequest,
			ID:   req.ID,
		},
		Address:     req.Address,
		TxnSender:   req.TxnSender,
		Description: req.Description,
		Timestamp:   req.Timestamp,
		FirstValid:  req.FirstValid,
		LastValid:   req.LastValid,
		Violations:  protocolViolations(req.Violations),
	}
}

func ProtocolSignRequestCanceledMessage(msg signerapproval.SignRequestCanceled) protocol.SignRequestCanceledMessage {
	return protocol.SignRequestCanceledMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeSignRequestCanceled,
			ID:   msg.ID,
		},
		Reason: msg.Reason,
	}
}

func ProtocolTokenProvisioningRequestMessage(req signerapproval.TokenProvisioningRequest) protocol.TokenProvisioningRequestMessage {
	return protocol.TokenProvisioningRequestMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeTokenProvisioningRequest,
			ID:   req.ID,
		},
		IdentityID:     req.IdentityID,
		SSHFingerprint: req.SSHFingerprint,
		RemoteAddr:     req.RemoteAddr,
		Timestamp:      req.Timestamp,
	}
}

func ProtocolSignerLockedMessage(notification adminproto.SignerLockedNotification) protocol.SignerLockedMessage {
	return protocol.SignerLockedMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSignerLocked},
		Reason:      notification.Reason,
	}
}

func ProtocolKeysChangedMessage(notification adminproto.KeysChangedNotification) protocol.KeysChangedMessage {
	return protocol.KeysChangedMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeKeysChanged},
		KeyCount:    notification.KeyCount,
	}
}

func protocolViolations(vs []signerapproval.Violation) []protocol.PolicyViolation {
	if len(vs) == 0 {
		return nil
	}
	out := make([]protocol.PolicyViolation, len(vs))
	for i, v := range vs {
		out[i] = protocol.PolicyViolation{
			Field:    v.Field,
			Value:    v.Value,
			Severity: string(v.Severity),
			Message:  v.Message,
		}
	}
	return out
}
