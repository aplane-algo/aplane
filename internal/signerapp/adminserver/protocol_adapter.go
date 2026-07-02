// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
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

func ProtocolUpdatePolicySettingResultMessage(id string, request adminproto.UpdatePolicySettingRequest, err error) protocol.UpdatePolicySettingResultMessage {
	result := protocol.UpdatePolicySettingResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeUpdatePolicySettingResult,
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

func ProtocolUpdatePolicyASAAmountsResultMessage(id string, err error) protocol.UpdatePolicyASAAmountsResultMessage {
	result := protocol.UpdatePolicyASAAmountsResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeUpdatePolicyASAResult,
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

func ProtocolRestoreBackupResultMessage(id string, result adminproto.RestoreBackupResult) protocol.RestoreBackupResultMessage {
	return protocol.RestoreBackupResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRestoreBackupResult,
			ID:   id,
		},
		ArchivePath: result.ArchivePath,
		Success:     result.Success,
		Restored:    protocolRestoreKeyInfos(result.Restored),
		Skipped:     protocolRestoreKeyInfos(result.Skipped),
		Errors:      protocolRestoreErrors(result.Errors),
		Warnings:    protocolRestoreWarnings(result.Warnings),
		KeyCount:    result.KeyCount,
		Code:        result.Code,
		Error:       result.Error,
	}
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

func protocolRestoreWarnings(items []adminproto.RestoreWarning) []protocol.RestoreWarning {
	if len(items) == 0 {
		return nil
	}
	out := make([]protocol.RestoreWarning, len(items))
	for i, item := range items {
		out[i] = protocol.RestoreWarning{
			Address: item.Address,
			KeyType: item.KeyType,
			Warning: item.Warning,
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

func ProtocolPolicySettingsMessage(requestID string, settings adminproto.PolicySettings) protocol.PolicySettingsMessage {
	return protocol.PolicySettingsMessage{
		BaseMessage:                 protocol.BaseMessage{Type: protocol.MsgTypePolicySettings, ID: requestID},
		RejectForeignRekey:          settings.RejectForeignRekey,
		RejectCloseRemainder:        settings.RejectCloseRemainder,
		RejectAssetClose:            settings.RejectAssetClose,
		RejectClawback:              settings.RejectClawback,
		AlwaysReviewWarnings:        settings.AlwaysReviewWarnings,
		AutoApproveSelfNoOpTransfer: settings.AutoApproveSelfNoOpTransfer,
		MaxFeeMicroAlgos:            settings.MaxFeeMicroAlgos,
		ReviewAlgoPayments:          clonePolicyStringMap(settings.ReviewAlgoPayments),
		MaxAlgoPayments:             clonePolicyStringMap(settings.MaxAlgoPayments),
		PolicyNetworks:              append([]string(nil), settings.PolicyNetworks...),
		ReviewASAAmounts:            clonePolicyStringMap(settings.ReviewASAAmounts),
		MaxASAAmounts:               clonePolicyStringMap(settings.MaxASAAmounts),
		PolicyASAMetadata:           protocolPolicyASAMetadata(settings.PolicyASAMetadata),
		MaxASAAmountsMainnet:        settings.MaxASAAmountsMainnet,
		MaxASAAmountsTestnet:        settings.MaxASAAmountsTestnet,
		MaxASAAmountsBetanet:        settings.MaxASAAmountsBetanet,
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

func ProtocolASAMetadataResultsMessage(result adminproto.ASAMetadataResults) protocol.ASAMetadataResultsMessage {
	return protocol.ASAMetadataResultsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeASAMetadataResults},
		Network:     result.Network,
		Query:       result.Query,
		Results:     protocolASAMetadataInfos(result.Results),
		Code:        result.Code,
		Error:       result.Error,
	}
}

func ProtocolASAMetadataResultMessage(result adminproto.ASAMetadataResult) protocol.ASAMetadataResultMessage {
	var asset *protocol.ASAMetadataInfo
	if result.Error == "" && result.Code == "" {
		info := protocolASAMetadataInfo(result.Asset)
		asset = &info
	}
	return protocol.ASAMetadataResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeASAMetadataResult},
		Network:     result.Network,
		Asset:       asset,
		Code:        result.Code,
		Error:       result.Error,
	}
}

func protocolASAMetadataInfos(in []adminproto.ASAMetadataInfo) []protocol.ASAMetadataInfo {
	if in == nil {
		return nil
	}
	out := make([]protocol.ASAMetadataInfo, len(in))
	for i, item := range in {
		out[i] = protocolASAMetadataInfo(item)
	}
	return out
}

func protocolPolicyASAMetadata(in map[string][]adminproto.ASAMetadataInfo) map[string][]protocol.ASAMetadataInfo {
	if in == nil {
		return nil
	}
	out := make(map[string][]protocol.ASAMetadataInfo, len(in))
	for network, items := range in {
		out[network] = protocolASAMetadataInfos(items)
	}
	return out
}

func protocolASAMetadataInfo(in adminproto.ASAMetadataInfo) protocol.ASAMetadataInfo {
	return protocol.ASAMetadataInfo{
		AssetID:  in.AssetID,
		Name:     in.Name,
		UnitName: in.UnitName,
		Decimals: in.Decimals,
		Source:   in.Source,
	}
}

func clonePolicyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
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

func ProtocolKeyInfos(keys []adminproto.KeyInfo) []protocol.KeyInfo {
	if len(keys) == 0 {
		return nil
	}
	out := make([]protocol.KeyInfo, len(keys))
	for i, key := range keys {
		out[i] = protocol.KeyInfo{
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
