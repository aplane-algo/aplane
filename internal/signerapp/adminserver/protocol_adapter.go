// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/txnreview"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func ProtocolStatusMessage(state string, keyCount int, warnings []string) protocol.StatusMessage {
	return protocol.StatusMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeStatus},
		State:       state,
		KeyCount:    keyCount,
		Warnings:    warnings,
	}
}

func ProtocolErrorMessage(requestID, code, errMsg string) protocol.ErrorMessage {
	if code == "" {
		code = protocol.ErrCodeInternal
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

func ProtocolEnrolledKeysListMessage(id string, keys []protocol.EnrolledKeyInfo) protocol.EnrolledKeysListMessage {
	if keys == nil {
		keys = []protocol.EnrolledKeyInfo{}
	}
	return protocol.EnrolledKeysListMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeEnrolledKeysList,
			ID:   id,
		},
		Keys: keys,
	}
}

func ProtocolPendingEnrollmentsListMessage(id string, requests []protocol.PendingEnrollmentInfo) protocol.PendingEnrollmentsListMessage {
	if requests == nil {
		requests = []protocol.PendingEnrollmentInfo{}
	}
	return protocol.PendingEnrollmentsListMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypePendingEnrollmentsList,
			ID:   id,
		},
		Requests: requests,
	}
}

func ProtocolApproveEnrollmentResultMessage(id, fingerprint, label string, err error) protocol.ApproveEnrollmentResultMessage {
	result := protocol.ApproveEnrollmentResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeApproveEnrollmentResult,
			ID:   id,
		},
		Success:     err == nil,
		Fingerprint: fingerprint,
		Label:       label,
	}
	if err != nil {
		result.Code = protocol.CodeForError(err)
		result.Error = err.Error()
	}
	return result
}

func ProtocolRejectEnrollmentResultMessage(id, fingerprint string, err error) protocol.RejectEnrollmentResultMessage {
	result := protocol.RejectEnrollmentResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRejectEnrollmentResult,
			ID:   id,
		},
		Success:     err == nil,
		Fingerprint: fingerprint,
	}
	if err != nil {
		result.Code = protocol.CodeForError(err)
		result.Error = err.Error()
	}
	return result
}

func ProtocolImportClientKeyResultMessage(id string, imported ImportedClientKey, err error) protocol.ImportClientKeyResultMessage {
	result := protocol.ImportClientKeyResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeImportClientKeyResult,
			ID:   id,
		},
		Success:        err == nil,
		Fingerprint:    imported.Fingerprint,
		Label:          imported.Label,
		Added:          imported.Added,
		CommentRefused: imported.CommentRefused,
	}
	if err != nil {
		result.Code = protocol.CodeForError(err)
		result.Error = err.Error()
	}
	return result
}

func ProtocolRevokeEnrolledKeyResultMessage(id string, closedConnections int, err error) protocol.RevokeEnrolledKeyResultMessage {
	result := protocol.RevokeEnrolledKeyResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRevokeEnrolledKeyResult,
			ID:   id,
		},
		Success:           err == nil,
		ClosedConnections: closedConnections,
	}
	if err != nil {
		result.Code = protocol.CodeForError(err)
		result.Error = err.Error()
	}
	return result
}

func ProtocolRevokeAllEnrolledKeysResultMessage(id string, revoked, closedConnections int, err error) protocol.RevokeAllEnrolledKeysResultMessage {
	result := protocol.RevokeAllEnrolledKeysResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRevokeAllEnrolledKeysResult,
			ID:   id,
		},
		Success:           err == nil,
		RevokedCount:      revoked,
		ClosedConnections: closedConnections,
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
		code = protocol.ErrCodeInternal
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
		ArchivePath:     publicArchiveName(result.ArchivePath),
		ArchiveChecksum: result.ArchiveChecksum,
		ArchiveSize:     result.ArchiveSize,
		KeyCount:        result.KeyCount,
		Addresses:       append([]string(nil), result.Addresses...),
		Verified:        result.Verified,
		Warning:         result.Warning,
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

func ProtocolBeginBackupImportResultMessage(id string, result adminproto.BeginBackupImportResult) protocol.BeginBackupImportResultMessage {
	return protocol.BeginBackupImportResultMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeBeginBackupImportResult, ID: id}, Success: result.Success, UploadID: result.UploadID, Code: result.Code, Error: result.Error}
}

func ProtocolAppendBackupImportResultMessage(id string, result adminproto.AppendBackupImportResult) protocol.AppendBackupImportResultMessage {
	return protocol.AppendBackupImportResultMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAppendBackupImportResult, ID: id}, Success: result.Success, NextOffset: result.NextOffset, Code: result.Code, Error: result.Error}
}

func ProtocolCommitBackupImportResultMessage(id string, result adminproto.CommitBackupImportResult) protocol.CommitBackupImportResultMessage {
	return protocol.CommitBackupImportResultMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeCommitBackupImportResult, ID: id}, Success: result.Success, Backup: protocolBackupInfo(result.Backup), Warning: result.Warning, Skipped: protocolRestoreSkipped(result.Skipped), SkippedOmitted: result.SkippedOmitted, Code: result.Code, Error: result.Error}
}

func ProtocolAbortBackupImportResultMessage(id string, result adminproto.AbortBackupImportResult) protocol.AbortBackupImportResultMessage {
	return protocol.AbortBackupImportResultMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAbortBackupImportResult, ID: id}, Success: result.Success, Code: result.Code, Error: result.Error}
}

func ProtocolBackupChunkMessage(id string, result adminproto.ReadBackupChunkResult) protocol.BackupChunkMessage {
	return protocol.BackupChunkMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeBackupChunk, ID: id}, Success: result.Success, FileName: result.FileName, Offset: result.Offset, Data: result.Data, EOF: result.EOF, Code: result.Code, Error: result.Error}
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
		Success:                result.Success,
		KeysMigrated:           result.KeysMigrated,
		TemplatesMigrated:      result.TemplatesMigrated,
		PolicySidecarsMigrated: result.PolicySidecarsMigrated,
		PriorGenerations:       result.PriorGenerations,
		HelperWarning:          result.HelperWarning,
		RootCommitted:          result.RootCommitted,
		Code:                   result.Code,
		Error:                  result.Error,
	}
}

func ProtocolRestorePreviewMessage(id string, result adminproto.RestorePreviewResult) protocol.RestorePreviewMessage {
	return protocol.RestorePreviewMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRestorePreview,
			ID:   id,
		},
		ArchivePath:      result.ArchivePath,
		ArchiveCreatedAt: result.ArchiveCreatedAt,
		Keys:             protocolRestoreKeyInfos(result.Keys),
		Skipped:          protocolRestoreSkipped(result.Skipped),
		SkippedOmitted:   result.SkippedOmitted,
		Code:             result.Code,
		Error:            result.Error,
	}
}

func ProtocolRestoreBackupResultMessage(id string, result adminproto.RestoreBackupResult) protocol.RestoreBackupResultMessage {
	return protocol.RestoreBackupResultMessage{
		BaseMessage:          protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackupResult, ID: id},
		Success:              result.Success,
		OperationID:          result.OperationID,
		ArchiveSHA256:        result.ArchiveSHA256,
		GenerationID:         result.GenerationID,
		Restored:             protocolRestoreCredentials(result.Restored),
		RestoredOmitted:      result.RestoredOmitted,
		Identical:            protocolRestoreCredentials(result.Identical),
		IdenticalOmitted:     result.IdenticalOmitted,
		Conflicts:            protocolRestoreConflicts(result.Conflicts),
		ConflictsOmitted:     result.ConflictsOmitted,
		Skipped:              protocolRestoreSkipped(result.Skipped),
		SkippedOmitted:       result.SkippedOmitted,
		PoliciesRestored:     result.PoliciesRestored,
		SourceTokensRestored: result.SourceTokensRestored,
		KeyCount:             result.KeyCount,
		Code:                 result.Code,
		Error:                result.Error,
	}
}

func ProtocolRollbackRestoreResultMessage(id string, result adminproto.RollbackRestoreResult) protocol.RollbackRestoreResultMessage {
	return protocol.RollbackRestoreResultMessage{
		BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypeRollbackRestoreResult, ID: id},
		Success:      result.Success,
		OperationID:  result.OperationID,
		GenerationID: result.GenerationID,
		KeyCount:     result.KeyCount,
		Code:         result.Code,
		Error:        result.Error,
	}
}

func ProtocolReconcileStoreResultMessage(id string, result adminproto.ReconcileStoreResult) protocol.ReconcileStoreResultMessage {
	return protocol.ReconcileStoreResultMessage{
		BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypeReconcileStoreResult, ID: id},
		Success:      result.Success,
		GenerationID: result.GenerationID,
		KeyCount:     result.KeyCount,
		State:        result.State,
		Code:         result.Code,
		Error:        result.Error,
	}
}

func protocolRestoreCredentials(items []adminproto.RestoreCredential) []protocol.RestoreCredential {
	out := make([]protocol.RestoreCredential, len(items))
	for i := range items {
		out[i] = protocol.RestoreCredential{
			Selector: items[i].Selector,
			Category: items[i].Category,
			KeyType:  items[i].KeyType,
		}
	}
	return out
}

func protocolRestoreConflicts(items []adminproto.RestoreConflict) []protocol.RestoreConflict {
	out := make([]protocol.RestoreConflict, len(items))
	for i := range items {
		out[i] = protocol.RestoreConflict{
			Selector:       items[i].Selector,
			Category:       items[i].Category,
			KeyType:        items[i].KeyType,
			ExistingSHA256: items[i].ExistingSHA256,
			Reason:         items[i].Reason,
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
		out[i] = protocolBackupInfo(item)
	}
	return out
}

// protocolBackupInfo names an archive by its base name only.
func protocolBackupInfo(item adminproto.BackupInfo) protocol.BackupInfo {
	return protocol.BackupInfo{
		FileName:  publicArchiveName(item.FileName),
		CreatedAt: item.CreatedAt,
		Size:      item.Size,
		Checksum:  item.Checksum,
	}
}

func publicArchiveName(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
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
			HasPolicy:     item.HasPolicy,
			StageHint:     item.StageHint, StageHintRound: item.StageHintRound,
			SourceTokens:        item.SourceTokens,
			SourceTokensOmitted: item.SourceTokensOmitted,
		}
	}
	return out
}

func protocolRestoreSkipped(items []adminproto.RestoreSkipped) []protocol.RestoreSkipped {
	if len(items) == 0 {
		return nil
	}
	out := make([]protocol.RestoreSkipped, len(items))
	for i, item := range items {
		out[i] = protocol.RestoreSkipped{Selector: item.Selector, Reason: item.Reason}
	}
	return out
}

func ProtocolAdminSettingsMessage(requestID string, settings adminproto.AdminSettings) protocol.AdminSettingsMessage {
	return protocol.AdminSettingsMessage{
		BaseMessage:          protocol.BaseMessage{Type: protocol.MsgTypeAdminSettings, ID: requestID},
		UserAutoApprove:      settings.UserAutoApprove,
		RequireContained:     settings.RequireContained,
		RequireCosigner:      settings.RequireCosigner,
		LockOnDisconnect:     settings.LockOnDisconnect,
		PassphraseTimeout:    settings.PassphraseTimeout,
		PassphraseMethod:     settings.PassphraseMethod,
		NodeRole:             settings.NodeRole,
		SSHListenAddress:     settings.SSHListenAddress,
		SSHPort:              settings.SSHPort,
		SSHFingerprint:       settings.SSHFingerprint,
		SSHClients:           settings.SSHClients,
		SignerPort:           settings.SignerPort,
		TEALCompileNet:       settings.TEALCompileNet,
		EndpointAdvertiseURL: settings.EndpointAdvertiseURL,
		EndpointDisplayURL:   settings.EndpointDisplayURL,
		Theme:                settings.Theme,
		UnsavedSettings:      settings.UnsavedSettings,
	}
}

func ProtocolPolicyDocumentMessage(id string, result adminproto.PolicyDocumentResult) protocol.PolicyDocumentMessage {
	return protocol.PolicyDocumentMessage{
		BaseMessage:       protocol.BaseMessage{Type: protocol.MsgTypePolicyDocument, ID: id},
		Success:           result.Success,
		Key:               result.Key,
		Document:          result.Document,
		SHA256:            result.SHA256,
		SignedAtUnix:      result.SignedAtUnix,
		SourceTokens:      result.SourceTokens,
		SourceTokensKnown: result.SourceTokensKnown,
		Code:              result.Code,
		Error:             result.Error,
	}
}

func ProtocolCheckPolicyResultMessage(id string, result adminproto.CheckPolicyResult) protocol.CheckPolicyResultMessage {
	return protocol.CheckPolicyResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeCheckPolicyResult, ID: id},
		Success:     result.Success,
		Valid:       result.Valid,
		Errors:      protocolPolicyProblems(result.Errors),
		Warnings:    protocolPolicyProblems(result.Warnings),
		Code:        result.Code,
		Error:       result.Error,
	}
}

func ProtocolApplyPolicyResultMessage(id string, result adminproto.ApplyPolicyResult) protocol.ApplyPolicyResultMessage {
	msg := protocol.ApplyPolicyResultMessage{
		BaseMessage:     protocol.BaseMessage{Type: protocol.MsgTypeApplyPolicyResult, ID: id},
		Success:         result.Success,
		Errors:          protocolPolicyProblems(result.Errors),
		CommitUncertain: result.CommitUncertain,
		Code:            result.Code,
		Error:           result.Error,
	}
	if result.Policy != nil {
		policyMsg := result.Policy.Wire(id)
		msg.Policy = &policyMsg
	}
	return msg
}

// AdminPolicyDocuments converts request documents to the admin domain.
func AdminPolicyDocuments(docs []protocol.PolicyDocumentWire) []adminproto.PolicyDocument {
	out := make([]adminproto.PolicyDocument, 0, len(docs))
	for _, doc := range docs {
		out = append(out, adminproto.PolicyDocument{Key: doc.Key, Document: doc.Document})
	}
	return out
}

func protocolPolicyProblems(problems []adminproto.PolicyProblem) []protocol.PolicyProblemWire {
	var out []protocol.PolicyProblemWire
	for _, problem := range problems {
		out = append(out, protocol.PolicyProblemWire{Key: problem.Key, Pointer: problem.Pointer, Message: problem.Message})
	}
	return out
}

func ProtocolCosignerReferencesListMessage(id string, result adminproto.ListCosignerReferencesResult) protocol.CosignerReferencesListMessage {
	refs := make([]protocol.CosignerReferenceInfo, len(result.References))
	for i := range result.References {
		refs[i] = protocolCosignerReference(result.References[i])
	}
	var invalid []protocol.InvalidCosignerReferenceInfo
	for _, bad := range result.Invalid {
		invalid = append(invalid, protocol.InvalidCosignerReferenceInfo{
			Path: bad.Path, Name: bad.Name, Reason: bad.Reason, Removable: bad.Removable,
		})
	}
	return protocol.CosignerReferencesListMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeCosignerReferencesList, ID: id},
		References:  refs, Invalid: invalid, Code: result.Code, Error: result.Error,
	}
}

func ProtocolCosignerReferenceMessage(id, messageType string, result adminproto.GetCosignerReferenceResult) protocol.CosignerReferenceMessage {
	return protocol.CosignerReferenceMessage{
		BaseMessage: protocol.BaseMessage{Type: messageType, ID: id}, Success: result.Success,
		Reference: protocolCosignerReference(result.Reference), Code: result.Code, Error: result.Error,
	}
}

func ProtocolRemoveCosignerReferenceResultMessage(id string, result adminproto.RemoveCosignerReferenceResult) protocol.RemoveCosignerReferenceResultMessage {
	return protocol.RemoveCosignerReferenceResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRemoveCosignerReferenceResult, ID: id},
		Success:     result.Success, Name: result.Name, Removed: result.Removed, Path: result.Path, Code: result.Code, Error: result.Error,
	}
}

func ProtocolExportCosignerPublicResultMessage(id string, result adminproto.ExportCosignerPublicResult) protocol.ExportCosignerPublicResultMessage {
	return protocol.ExportCosignerPublicResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeExportCosignerPublicResult, ID: id},
		Success:     result.Success, WitnessKeyID: result.WitnessKeyID, EnvelopeJSON: result.EnvelopeJSON,
		Code: result.Code, Error: result.Error,
	}
}

func ProtocolGenerationsListMessage(id string, result adminproto.GenerationInventory) protocol.GenerationsListMessage {
	quarantined := make([]protocol.QuarantinedGenerationInfo, 0, len(result.Quarantined))
	for _, item := range result.Quarantined {
		quarantined = append(quarantined, protocol.QuarantinedGenerationInfo{
			GenerationID: item.GenerationID, ParentID: item.ParentID,
			ManifestSHA256: item.ManifestSHA256, LiveInventorySHA256: item.LiveInventorySHA256,
			AtMintInventoryMatch: item.AtMintInventoryMatch,
			EntryCount:           item.EntryCount, EncodedBytes: item.EncodedBytes,
			TermVerified: item.TermVerified, TermUnavailable: item.TermUnavailable,
			TermFailed: item.TermFailed,
		})
	}
	return protocol.GenerationsListMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGenerationsList, ID: id},
		Current:     result.Current, SealedPriors: result.SealedPriors,
		Quarantined: quarantined, PendingStaging: result.PendingStaging,
		RetainedUnsealedParent: result.RetainedUnsealedParent, Code: result.Code, Error: result.Error,
	}
}

func ProtocolPruneGenerationQuarantineResultMessage(
	id string,
	result adminproto.PruneGenerationQuarantineResult,
) protocol.PruneGenerationQuarantineResultMessage {
	pruned := make([]protocol.PrunedQuarantinedGeneration, 0, len(result.Pruned))
	for _, item := range result.Pruned {
		pruned = append(pruned, protocol.PrunedQuarantinedGeneration{
			GenerationID:  item.GenerationID,
			EncodedBytes:  item.EncodedBytes,
			AlreadyAbsent: item.AlreadyAbsent,
		})
	}
	return protocol.PruneGenerationQuarantineResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypePruneGenerationQuarantineResult,
			ID:   id,
		},
		Success: result.Success,
		Pruned:  pruned,
		Code:    result.Code,
		Error:   result.Error,
	}
}

func ProtocolDiscardAbandonedGenerationsResultMessage(
	id string,
	result adminproto.DiscardAbandonedGenerationsResult,
) protocol.DiscardAbandonedGenerationsResultMessage {
	discarded := make([]protocol.PrunedQuarantinedGeneration, 0, len(result.Discarded))
	for _, item := range result.Discarded {
		discarded = append(discarded, protocol.PrunedQuarantinedGeneration{
			GenerationID: item.GenerationID, EncodedBytes: item.EncodedBytes,
			AlreadyAbsent: item.AlreadyAbsent,
		})
	}
	return protocol.DiscardAbandonedGenerationsResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDiscardAbandonedGenerationsResult, ID: id},
		Success:     result.Success, Discarded: discarded, Code: result.Code, Error: result.Error,
	}
}

func ProtocolDeletedArchiveListMessage(id string, result adminproto.DeletedArchiveInventory) protocol.DeletedArchiveListMessage {
	entries := make([]protocol.DeletedArchiveEntry, 0, len(result.Entries))
	for _, item := range result.Entries {
		entries = append(entries, protocol.DeletedArchiveEntry{Path: item.Path, EncodedBytes: item.EncodedBytes})
	}
	return protocol.DeletedArchiveListMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDeletedArchiveList, ID: id},
		Entries:     entries, EntryCount: result.EntryCount, EncodedBytes: result.EncodedBytes,
		Warning: result.Warning, Code: result.Code, Error: result.Error,
	}
}

func ProtocolPruneDeletedArchiveResultMessage(id string, result adminproto.PruneDeletedArchiveResult) protocol.PruneDeletedArchiveResultMessage {
	pruned := make([]protocol.PrunedDeletedArchiveEntry, 0, len(result.Pruned))
	for _, item := range result.Pruned {
		pruned = append(pruned, protocol.PrunedDeletedArchiveEntry{
			Path: item.Path, EncodedBytes: item.EncodedBytes, AlreadyAbsent: item.AlreadyAbsent,
		})
	}
	return protocol.PruneDeletedArchiveResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePruneDeletedArchiveResult, ID: id},
		Success:     result.Success, Pruned: pruned, Code: result.Code, Error: result.Error,
	}
}

func protocolCosignerReference(item adminproto.CosignerReferenceInfo) protocol.CosignerReferenceInfo {
	return protocol.CosignerReferenceInfo{
		Schema: item.Schema, Name: item.Name, ComponentKey: item.ComponentKey, KeyType: item.KeyType,
		PublicKeyHex: item.PublicKeyHex, ImportedAt: item.ImportedAt,
	}
}

func ProtocolPrepareGenerateResultMessage(id string, result adminproto.PrepareGenerateKeyResult) protocol.PrepareGenerateResultMessage {
	message := protocol.PrepareGenerateResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypePrepareGenerateResult,
			ID:   id,
		},
		Success:           result.Success,
		KeyType:           result.KeyType,
		BaseKeyType:       result.BaseKeyType,
		Parameters:        result.Parameters,
		Fingerprint:       result.Fingerprint,
		ReviewFingerprint: result.ReviewFingerprint,
		BoundaryDigest:    result.BoundaryDigest,
		CosignerKeyID:     result.CosignerKeyID,
		Warnings:          result.Warnings,
		Code:              result.Code,
		Error:             result.Error,
	}
	if profile := result.Bounded; profile != nil {
		message.Bounded = &protocol.PreparedBoundedProfile{
			Contract:         profile.Contract,
			SpendEffects:     profile.SpendEffects,
			MaxFee:           boundedmeta.CloneMaxFee(profile.MaxFee),
			Rekey:            profile.Rekey,
			RekeyList:        profile.RekeyList,
			Layer3Policy:     profile.Layer3Policy,
			CosignerRequired: profile.CosignerRequired,
			CosignerKeyType:  profile.CosignerKeyType,
		}
	}
	return message
}

func ProtocolGenerateResultMessage(id string, result adminproto.GenerateKeyResult) protocol.GenerateResultMessage {
	return protocol.GenerateResultMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeGenerateResult,
			ID:   id,
		},
		Success:    result.Success,
		Address:    result.Address,
		KeyType:    result.KeyType,
		Parameters: result.Parameters,
		Warnings:   result.Warnings,
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
		PolicyLabel:              result.PolicyLabel,
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
			KeyType:                   item.KeyType,
			Family:                    item.Family,
			DisplayName:               item.DisplayName,
			Description:               item.Description,
			AuthorizationKind:         item.AuthorizationKind,
			MnemonicWordCount:         item.MnemonicWordCount,
			MnemonicImport:            item.MnemonicImport,
			MnemonicScheme:            item.MnemonicScheme,
			CosignerComponentKeyTypes: append([]string(nil), item.CosignerComponentKeyTypes...),
			PerKeyContract:            item.PerKeyContract,
			BoundarySchema:            item.BoundarySchema,
			CreationParams:            protocolCreationParams(item.CreationParams),
			RuntimeArgs:               protocolRuntimeArgs(item.RuntimeArgs),
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
		Review:      protocolReview(req.Review),
	}
}

// protocolReview is a review in its wire form.
func protocolReview(review *txnreview.Review) *protocol.Review {
	if review == nil {
		return nil
	}
	fields := func(in []txnreview.Field) []protocol.ReviewField {
		if len(in) == 0 {
			return nil
		}
		out := make([]protocol.ReviewField, len(in))
		for i, f := range in {
			out[i] = protocol.ReviewField{Label: f.Label, Value: f.Value, Party: f.Party, Alert: f.Alert, Depth: f.Depth}
		}
		return out
	}
	findings := func(in []txnreview.Finding) []protocol.PolicyViolation {
		var out []protocol.PolicyViolation
		for _, f := range in {
			out = append(out, protocol.PolicyViolation{Field: f.Field, Value: f.Value, Severity: f.Level(), Message: f.Message})
		}
		return out
	}
	out := &protocol.Review{
		Version: protocol.ReviewVersion,
		Group:   review.Group,
		Banners: review.Banners,
		Changes: protocol.ReviewChanges{
			Heading: review.Changes.Heading, Lines: review.Changes.Lines,
			Frozen: review.Changes.Frozen, Dummies: review.Changes.Dummies, FeeAdded: review.Changes.FeeAdded,
		},
		Items: make([]protocol.ReviewItem, len(review.Items)),
	}
	for i, item := range review.Items {
		wire := protocol.ReviewItem{
			Position: string(item.Position), Label: item.Label, Notes: fields(item.Notes), Claims: item.Claims,
			Title: item.Details.Title, Sender: item.Details.Sender, Fields: fields(item.Details.Fields),
		}
		for _, e := range item.Details.Effects {
			wire.Effects = append(wire.Effects, protocol.ReviewEffect{
				Kind: string(e.Kind), From: e.From, To: e.To, Authority: e.Authority,
				App: e.App, NewApp: e.NewApp, Text: e.Text, Severity: string(e.Severity),
			})
		}
		wire.Findings = findings(item.Findings)
		out.Items[i] = wire
	}
	for _, p := range review.Parties {
		party := protocol.ReviewParty{Address: p.Address, Held: p.Held, Signs: p.Signs, KeyType: p.KeyType, Lookalike: p.Lookalike, Signable: p.Signable}
		if p.MicroAlgos != nil {
			balance := *p.MicroAlgos
			party.MicroAlgos = &balance
		}
		out.Parties = append(out.Parties, party)
	}
	out.Findings = findings(review.Findings)
	if c := review.Chain; c != nil {
		out.Chain = &protocol.ReviewChain{Round: c.Round, Unavailable: c.Unavailable}
	}
	if b := review.Batch; b != nil {
		out.Batch = &protocol.ReviewBatch{Position: b.Position, Count: b.Count}
	}
	return out
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

func ProtocolClientEnrollmentRequestMessage(req signerapproval.ClientEnrollmentRequest) protocol.ClientEnrollmentRequestMessage {
	return protocol.ClientEnrollmentRequestMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeClientEnrollmentRequest,
			ID:   req.ID,
		},
		SSHFingerprint: req.SSHFingerprint,
		Label:          req.Label,
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

func ProtocolEnrollmentChangedMessage(notification adminproto.EnrollmentChangedNotification) protocol.EnrollmentChangedMessage {
	return protocol.EnrollmentChangedMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeEnrollmentChanged},
		Reason:      notification.Reason,
		Fingerprint: notification.Fingerprint,
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
