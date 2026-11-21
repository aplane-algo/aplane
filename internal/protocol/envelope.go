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
		MsgTypePrepareGenerateKey,
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
		MsgTypeGetPolicyContext,
		MsgTypeListASASet,
		MsgTypeLookupASA,
		MsgTypeAddASA,
		MsgTypeRemoveASA,
		MsgTypeSourceTokenSet,
		MsgTypeSourceTokenRemove,
		MsgTypeSourceTokenList,
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
		MsgTypePrepareGenerateResult,
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
		MsgTypePolicyContext,
		MsgTypeASASet,
		MsgTypeLookupASAResult,
		MsgTypeAddASAResult,
		MsgTypeRemoveASAResult,
		MsgTypeSourceTokenSetResult,
		MsgTypeSourceTokenRemoveResult,
		MsgTypeSourceTokenListResult,
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

// MarshalAdminMessage encodes an admin message, adding the kind its type
// implies when it has none. The kind is appended to the encoded object rather
// than added by decoding and encoding the message again, and the first
// encoding is zeroed, so a message that carries a passphrase or a recovery
// phrase leaves no copy of it here beyond the frame it returns, which the
// caller zeroes. encoding/json's own pooled buffers still keep copies.
func MarshalAdminMessage(v interface{}) ([]byte, error) {
	data, err := marshalAdminJSON(v)
	if err != nil {
		return nil, err
	}

	var base BaseMessage
	if err := json.Unmarshal(data, &base); err != nil {
		SensitiveBytes(data).Zero()
		return nil, err
	}
	if base.Type == "" || base.Kind != "" {
		return data, nil
	}

	inferred, ok := InferMessageKind(base.Type)
	if !ok {
		return data, nil
	}
	framed, err := appendObjectKind(data, inferred)
	SensitiveBytes(data).Zero()
	if err != nil {
		return nil, err
	}
	return framed, nil
}

// appendObjectKind returns a copy of the encoded object with a kind member
// added last, so it overrides any empty kind the object already carries.
func appendObjectKind(object []byte, kind MessageKind) ([]byte, error) {
	if len(object) < 2 || object[0] != '{' || object[len(object)-1] != '}' {
		return nil, fmt.Errorf("admin message with a type must encode as a JSON object")
	}
	kindJSON, err := json.Marshal(kind)
	if err != nil {
		return nil, err
	}
	const member = `"kind":`
	out := make([]byte, 0, len(object)+1+len(member)+len(kindJSON))
	out = append(out, object[:len(object)-1]...)
	if len(object) > 2 {
		out = append(out, ',')
	}
	out = append(out, member...)
	out = append(out, kindJSON...)
	return append(out, '}'), nil
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
