// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func InferMessageKind(messageType string) (MessageKind, bool) {
	switch messageType {
	case MsgTypeAuth,
		MsgTypeAuthOnly,
		MsgTypeUnlock,
		MsgTypeLockIdentity,
		MsgTypeInitializeStore,
		MsgTypeChangeStorePass,
		MsgTypeBackup,
		MsgTypeListBackups,
		MsgTypeDeleteBackup,
		MsgTypeBeginBackupImport,
		MsgTypeAppendBackupImport,
		MsgTypeCommitBackupImport,
		MsgTypeAbortBackupImport,
		MsgTypeReadBackupChunk,
		MsgTypePreviewRestore,
		MsgTypeRestoreBackup,
		MsgTypeRollbackRestore,
		MsgTypeReconcileStore,
		MsgTypeSignResponse,
		MsgTypeListPendingEnrollments,
		MsgTypeApproveEnrollment,
		MsgTypeRejectEnrollment,
		MsgTypeImportClientKey,
		MsgTypeListEnrolledKeys,
		MsgTypeRevokeEnrolledKey,
		MsgTypeRevokeAllEnrolledKeys,
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
		MsgTypeGetPolicy,
		MsgTypeGetPolicyDocument,
		MsgTypeCheckPolicy,
		MsgTypeApplyPolicy,
		MsgTypeListCosignerReferences,
		MsgTypeGetCosignerReference,
		MsgTypeImportCosignerReference,
		MsgTypeRemoveCosignerReference,
		MsgTypeExportCosignerPublic,
		MsgTypeListGenerations,
		MsgTypePruneGenerationQuarantine,
		MsgTypeDiscardAbandonedGenerations,
		MsgTypeListDeletedArchive,
		MsgTypePruneDeletedArchive,
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
		MsgTypeBeginBackupImportResult,
		MsgTypeAppendBackupImportResult,
		MsgTypeCommitBackupImportResult,
		MsgTypeAbortBackupImportResult,
		MsgTypeBackupChunk,
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
		MsgTypeEnrolledKeysList,
		MsgTypeRevokeEnrolledKeyResult,
		MsgTypeRevokeAllEnrolledKeysResult,
		MsgTypePendingEnrollmentsList,
		MsgTypeApproveEnrollmentResult,
		MsgTypeRejectEnrollmentResult,
		MsgTypeImportClientKeyResult,
		MsgTypeAdminSettings,
		MsgTypeUpdateAdminSettingResult,
		MsgTypePolicy,
		MsgTypePolicyDocument,
		MsgTypeCheckPolicyResult,
		MsgTypeApplyPolicyResult,
		MsgTypeCosignerReferencesList,
		MsgTypeCosignerReference,
		MsgTypeImportCosignerReferenceResult,
		MsgTypeRemoveCosignerReferenceResult,
		MsgTypeExportCosignerPublicResult,
		MsgTypeGenerationsList,
		MsgTypePruneGenerationQuarantineResult,
		MsgTypeDiscardAbandonedGenerationsResult,
		MsgTypeDeletedArchiveList,
		MsgTypePruneDeletedArchiveResult:
		return MessageKindResponse, true
	case MsgTypeAuthRequired,
		MsgTypeStatus,
		MsgTypeSignRequest,
		MsgTypeSignRequestCanceled,
		MsgTypeClientEnrollmentRequest,
		MsgTypeKeysChanged,
		MsgTypeEnrollmentChanged,
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
	data, err := marshalAdminJSON(v)
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

	kindBytes, err := marshalAdminJSON(inferred)
	if err != nil {
		return nil, err
	}
	object["kind"] = kindBytes
	return marshalAdminJSON(object)
}

// marshalAdminJSON encodes v without HTML escaping. Admin messages never reach
// an HTML context, and escaping <, >, and & as six-byte sequences would let a
// valid policy document grow past the frame limit. Without it a string at
// most doubles: only quotes, backslashes, JSON whitespace, and U+2028/U+2029
// are escaped, and none of them grows by more than its own size.
func marshalAdminJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
