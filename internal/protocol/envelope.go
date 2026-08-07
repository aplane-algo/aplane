// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"encoding/json"
	"fmt"
)

func InferMessageKind(messageType string) (MessageKind, bool) {
	switch messageType {
	case MsgTypeAuth,
		MsgTypeUnlock,
		MsgTypeLockIdentity,
		MsgTypeInitializeStore,
		MsgTypeChangeStorePass,
		MsgTypeBackup,
		MsgTypeListBackups,
		MsgTypeDeleteBackup,
		MsgTypePreviewRestore,
		MsgTypeRestoreBackup,
		MsgTypeRollbackRestore,
		MsgTypeReconcileStore,
		MsgTypeSignResponse,
		MsgTypeTokenProvisioningResponse,
		MsgTypeRevokeToken,
		MsgTypeListKeys,
		MsgTypeGenerateKey,
		MsgTypeDeleteKey,
		MsgTypeExportKey,
		MsgTypeImportKey,
		MsgTypeGetKeyDetails,
		MsgTypeListLibraryTemplates,
		MsgTypeInstallLibraryTemplate,
		MsgTypeListInstalledTemplates,
		MsgTypeShowInstalledTemplate,
		MsgTypeShowLibraryTemplate,
		MsgTypeImportInstalledTemplate,
		MsgTypeRemoveInstalledTemplate,
		MsgTypeActivateKeyType,
		MsgTypeDeactivateKeyType,
		MsgTypeListKeyTypes,
		MsgTypeGetAdminSettings,
		MsgTypeUpdateAdminSetting,
		MsgTypeGetPolicySnapshot,
		MsgTypeReplacePolicy,
		MsgTypeValidatePolicy,
		MsgTypeDisplaceConfirm:
		return MessageKindRequest, true
	case MsgTypeAuthResult,
		MsgTypeUnlockResult,
		MsgTypeLockIdentityResult,
		MsgTypeInitializeStoreResult,
		MsgTypeChangeStorePassResult,
		MsgTypeBackupResult,
		MsgTypeBackupsList,
		MsgTypeDeleteBackupResult,
		MsgTypeRestorePreview,
		MsgTypeRestoreBackupResult,
		MsgTypeRollbackRestoreResult,
		MsgTypeReconcileStoreResult,
		MsgTypeError,
		MsgTypeKeysList,
		MsgTypeGenerateResult,
		MsgTypeDeleteResult,
		MsgTypeExportResult,
		MsgTypeImportResult,
		MsgTypeKeyDetails,
		MsgTypeLibraryTemplates,
		MsgTypeInstallLibraryTemplateResult,
		MsgTypeInstalledTemplates,
		MsgTypeShowInstalledTemplateResult,
		MsgTypeShowLibraryTemplateResult,
		MsgTypeImportInstalledTemplateResult,
		MsgTypeRemoveInstalledTemplateResult,
		MsgTypeActivateKeyTypeResult,
		MsgTypeDeactivateKeyTypeResult,
		MsgTypeKeyTypes,
		MsgTypeRevokeTokenResult,
		MsgTypeAdminSettings,
		MsgTypeUpdateAdminSettingResult,
		MsgTypePolicySnapshot,
		MsgTypeReplacePolicyResult,
		MsgTypeValidatePolicyResult:
		return MessageKindResponse, true
	case MsgTypeAuthRequired,
		MsgTypeStatus,
		MsgTypeSignRequest,
		MsgTypeSignRequestCanceled,
		MsgTypeTokenProvisioningRequest,
		MsgTypeKeysChanged,
		MsgTypeSignerLocked,
		MsgTypeClientExists,
		MsgTypeDisplaced:
		return MessageKindNotification, true
	default:
		return "", false
	}
}

func ParseAdminBaseMessage(data []byte) (BaseMessage, error) {
	var base BaseMessage
	if err := json.Unmarshal(data, &base); err != nil {
		return BaseMessage{}, err
	}
	if base.Kind == "" {
		return BaseMessage{}, fmt.Errorf("missing admin message kind")
	}
	switch base.Kind {
	case MessageKindRequest, MessageKindResponse, MessageKindNotification:
		return base, nil
	default:
		return BaseMessage{}, fmt.Errorf("invalid admin message kind: %s", base.Kind)
	}
}

func MarshalAdminMessage(v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var base BaseMessage
	if err := json.Unmarshal(data, &base); err != nil {
		return nil, err
	}
	if base.Type == "" || base.Kind != "" {
		return data, nil
	}

	inferred, ok := InferMessageKind(base.Type)
	if !ok {
		return data, nil
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}

	kindBytes, err := json.Marshal(inferred)
	if err != nil {
		return nil, err
	}
	object["kind"] = kindBytes
	return json.Marshal(object)
}
