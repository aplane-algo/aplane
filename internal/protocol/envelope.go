// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
)

func InferMessageKind(messageType string) (MessageKind, bool) {
	switch messageType {
	case MsgTypeAuth,
		MsgTypeAuthOnly,
		MsgTypeUnlock,
		MsgTypeLockIdentity,
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

// MarshalAdminMessage encodes an admin message, setting the kind its type
// implies when it has none. When v is a struct (or pointer to struct) carrying
// BaseMessage, Kind is populated on a shallow struct copy before encoding once:
// SensitiveBytes fields share their backing array across the shallow copy, no
// intermediate JSON copy of a passphrase or recovery phrase is created, and
// caller pointers are never mutated. encoding/json's own pooled buffers still
// keep copies.
func MarshalAdminMessage(v interface{}) ([]byte, error) {
	return marshalAdminJSON(withInferredKind(v))
}

var baseMessageType = reflect.TypeOf(BaseMessage{})

func withInferredKind(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return v
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return v
	}
	baseField, ok := findBaseMessage(rv)
	if !ok {
		return v
	}
	base := baseField.Interface().(BaseMessage)
	if base.Type == "" || base.Kind != "" {
		return v
	}
	inferred, ok := InferMessageKind(base.Type)
	if !ok {
		return v
	}
	clone := reflect.New(rv.Type())
	clone.Elem().Set(rv)
	cloneBase, _ := findBaseMessage(clone.Elem())
	base.Kind = inferred
	cloneBase.Set(reflect.ValueOf(base))
	return clone.Interface()
}

func findBaseMessage(rv reflect.Value) (reflect.Value, bool) {
	if rv.Type() == baseMessageType {
		return rv, true
	}
	t := rv.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous && f.Type == baseMessageType {
			return rv.Field(i), true
		}
	}
	return reflect.Value{}, false
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
