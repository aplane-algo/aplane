// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"github.com/aplane-algo/aplane/internal/protocol"
)

// Re-export protocol message type constants for convenience within the tui package.
// This allows other files in this package to use these constants without the protocol prefix.
const (
	// Authentication message types
	MsgTypeAuthRequired = protocol.MsgTypeAuthRequired
	MsgTypeAuth         = protocol.MsgTypeAuth
	MsgTypeAuthResult   = protocol.MsgTypeAuthResult

	// Signer state message types
	MsgTypeUnlock                = protocol.MsgTypeUnlock
	MsgTypeUnlockResult          = protocol.MsgTypeUnlockResult
	MsgTypeLockIdentity          = protocol.MsgTypeLockIdentity
	MsgTypeLockIdentityResult    = protocol.MsgTypeLockIdentityResult
	MsgTypeBackup                = protocol.MsgTypeBackup
	MsgTypeBackupResult          = protocol.MsgTypeBackupResult
	MsgTypeListBackups           = protocol.MsgTypeListBackups
	MsgTypeBackupsList           = protocol.MsgTypeBackupsList
	MsgTypePreviewRestore        = protocol.MsgTypePreviewRestore
	MsgTypeRestorePreview        = protocol.MsgTypeRestorePreview
	MsgTypeRestoreBackup         = protocol.MsgTypeRestoreBackup
	MsgTypeRestoreBackupResult   = protocol.MsgTypeRestoreBackupResult
	MsgTypeRollbackRestore       = protocol.MsgTypeRollbackRestore
	MsgTypeRollbackRestoreResult = protocol.MsgTypeRollbackRestoreResult
	MsgTypeReconcileStore        = protocol.MsgTypeReconcileStore
	MsgTypeReconcileStoreResult  = protocol.MsgTypeReconcileStoreResult
	MsgTypeSignRequest           = protocol.MsgTypeSignRequest
	MsgTypeSignResponse          = protocol.MsgTypeSignResponse
	MsgTypeStatus                = protocol.MsgTypeStatus
	MsgTypeError                 = protocol.MsgTypeError

	// Token provisioning message types
	MsgTypeTokenProvisioningRequest      = protocol.MsgTypeTokenProvisioningRequest
	MsgTypeTokenProvisioningResponse     = protocol.MsgTypeTokenProvisioningResponse
	MsgTypeRevokeToken                   = protocol.MsgTypeRevokeToken
	MsgTypeRevokeTokenResult             = protocol.MsgTypeRevokeTokenResult
	MsgTypeListKeys                      = protocol.MsgTypeListKeys
	MsgTypeKeysList                      = protocol.MsgTypeKeysList
	MsgTypeGenerateKey                   = protocol.MsgTypeGenerateKey
	MsgTypeGenerateResult                = protocol.MsgTypeGenerateResult
	MsgTypeDeleteKey                     = protocol.MsgTypeDeleteKey
	MsgTypeDeleteResult                  = protocol.MsgTypeDeleteResult
	MsgTypeImportKey                     = protocol.MsgTypeImportKey
	MsgTypeImportResult                  = protocol.MsgTypeImportResult
	MsgTypeGetKeyDetails                 = protocol.MsgTypeGetKeyDetails
	MsgTypeKeyDetails                    = protocol.MsgTypeKeyDetails
	MsgTypeListLibraryTemplates          = protocol.MsgTypeListLibraryTemplates
	MsgTypeLibraryTemplates              = protocol.MsgTypeLibraryTemplates
	MsgTypeInstallLibraryTemplate        = protocol.MsgTypeInstallLibraryTemplate
	MsgTypeInstallLibraryTemplateResult  = protocol.MsgTypeInstallLibraryTemplateResult
	MsgTypeShowLibraryTemplate           = protocol.MsgTypeShowLibraryTemplate
	MsgTypeShowLibraryTemplateResult     = protocol.MsgTypeShowLibraryTemplateResult
	MsgTypeActivateKeyType               = protocol.MsgTypeActivateKeyType
	MsgTypeActivateKeyTypeResult         = protocol.MsgTypeActivateKeyTypeResult
	MsgTypeDeactivateKeyType             = protocol.MsgTypeDeactivateKeyType
	MsgTypeDeactivateKeyTypeResult       = protocol.MsgTypeDeactivateKeyTypeResult
	MsgTypeListKeyTypes                  = protocol.MsgTypeListKeyTypes
	MsgTypeKeyTypes                      = protocol.MsgTypeKeyTypes
	MsgTypeListCosignerReferences        = protocol.MsgTypeListCosignerReferences
	MsgTypeCosignerReferencesList        = protocol.MsgTypeCosignerReferencesList
	MsgTypeImportCosignerReference       = protocol.MsgTypeImportCosignerReference
	MsgTypeImportCosignerReferenceResult = protocol.MsgTypeImportCosignerReferenceResult
	MsgTypeRemoveCosignerReference       = protocol.MsgTypeRemoveCosignerReference
	MsgTypeRemoveCosignerReferenceResult = protocol.MsgTypeRemoveCosignerReferenceResult
	MsgTypeExportCosignerPublic          = protocol.MsgTypeExportCosignerPublic
	MsgTypeExportCosignerPublicResult    = protocol.MsgTypeExportCosignerPublicResult

	// Server-initiated notification message types
	MsgTypeSignRequestCanceled = protocol.MsgTypeSignRequestCanceled
	MsgTypeKeysChanged         = protocol.MsgTypeKeysChanged
	MsgTypeSignerLocked        = protocol.MsgTypeSignerLocked

	// Admin settings message types
	MsgTypeGetAdminSettings         = protocol.MsgTypeGetAdminSettings
	MsgTypeAdminSettings            = protocol.MsgTypeAdminSettings
	MsgTypePolicy                   = protocol.MsgTypePolicy
	MsgTypePolicyDocument           = protocol.MsgTypePolicyDocument
	MsgTypeCheckPolicyResult        = protocol.MsgTypeCheckPolicyResult
	MsgTypeApplyPolicyResult        = protocol.MsgTypeApplyPolicyResult
	MsgTypeUpdateAdminSetting       = protocol.MsgTypeUpdateAdminSetting
	MsgTypeUpdateAdminSettingResult = protocol.MsgTypeUpdateAdminSettingResult

	// Client displacement message types
	MsgTypeClientExists    = protocol.MsgTypeClientExists
	MsgTypeDisplaceConfirm = protocol.MsgTypeDisplaceConfirm
	MsgTypeDisplaced       = protocol.MsgTypeDisplaced
)

// Type aliases for protocol message types (wire format types)
type (
	BaseMessage                          = protocol.BaseMessage
	ProtocolVersion                      = protocol.ProtocolVersion
	AuthRequiredMessage                  = protocol.AuthRequiredMessage
	AuthMessage                          = protocol.AuthMessage
	AuthResultMessage                    = protocol.AuthResultMessage
	UnlockMessage                        = protocol.UnlockMessage
	UnlockResultMessage                  = protocol.UnlockResultMessage
	LockIdentityMessage                  = protocol.LockIdentityMessage
	LockIdentityResultMessage            = protocol.LockIdentityResultMessage
	BackupMessage                        = protocol.BackupMessage
	BackupResultMessage                  = protocol.BackupResultMessage
	ListBackupsMessage                   = protocol.ListBackupsMessage
	BackupInfo                           = protocol.BackupInfo
	BackupsListMessage                   = protocol.BackupsListMessage
	PreviewRestoreMessage                = protocol.PreviewRestoreMessage
	SensitiveBytes                       = protocol.SensitiveBytes
	RestoreKeyInfo                       = protocol.RestoreKeyInfo
	RestoreError                         = protocol.RestoreError
	RestorePreviewMessage                = protocol.RestorePreviewMessage
	RestoreBackupMessage                 = protocol.RestoreBackupMessage
	RestoreBackupResultMessage           = protocol.RestoreBackupResultMessage
	RollbackRestoreMessage               = protocol.RollbackRestoreMessage
	RollbackRestoreResultMessage         = protocol.RollbackRestoreResultMessage
	ReconcileStoreMessage                = protocol.ReconcileStoreMessage
	ReconcileStoreResultMessage          = protocol.ReconcileStoreResultMessage
	RestoreCredential                    = protocol.RestoreCredential
	RestoreConflict                      = protocol.RestoreConflict
	SignRequestMessage                   = protocol.SignRequestMessage
	SignRequestCanceledMessage           = protocol.SignRequestCanceledMessage
	SignResponseMessage                  = protocol.SignResponseMessage
	StatusMessage                        = protocol.StatusMessage
	ErrorMessage                         = protocol.ErrorMessage
	ListKeysMessage                      = protocol.ListKeysMessage
	KeysListMessage                      = protocol.KeysListMessage
	GenerateKeyMessage                   = protocol.GenerateKeyMessage
	GenerateResultMessage                = protocol.GenerateResultMessage
	DeleteKeyMessage                     = protocol.DeleteKeyMessage
	DeleteResultMessage                  = protocol.DeleteResultMessage
	ImportKeyMessage                     = protocol.ImportKeyMessage
	ImportResultMessage                  = protocol.ImportResultMessage
	GetKeyDetailsMessage                 = protocol.GetKeyDetailsMessage
	KeyDetailsMessage                    = protocol.KeyDetailsMessage
	ListLibraryTemplatesMessage          = protocol.ListLibraryTemplatesMessage
	LibraryTemplatesMessage              = protocol.LibraryTemplatesMessage
	InstallLibraryTemplateMessage        = protocol.InstallLibraryTemplateMessage
	InstallLibraryTemplateResultMessage  = protocol.InstallLibraryTemplateResultMessage
	ShowLibraryTemplateMessage           = protocol.ShowLibraryTemplateMessage
	ShowLibraryTemplateResultMessage     = protocol.ShowLibraryTemplateResultMessage
	ActivateKeyTypeMessage               = protocol.ActivateKeyTypeMessage
	ActivateKeyTypeResultMessage         = protocol.ActivateKeyTypeResultMessage
	DeactivateKeyTypeMessage             = protocol.DeactivateKeyTypeMessage
	DeactivateKeyTypeResultMessage       = protocol.DeactivateKeyTypeResultMessage
	ListKeyTypesMessage                  = protocol.ListKeyTypesMessage
	KeyTypesMessage                      = protocol.KeyTypesMessage
	ListCosignerReferencesMessage        = protocol.ListCosignerReferencesMessage
	CosignerReferencesListMessage        = protocol.CosignerReferencesListMessage
	CosignerReferenceInfo                = protocol.CosignerReferenceInfo
	ImportCosignerReferenceMessage       = protocol.ImportCosignerReferenceMessage
	ImportCosignerReferenceResultMessage = protocol.ImportCosignerReferenceResultMessage
	RemoveCosignerReferenceMessage       = protocol.RemoveCosignerReferenceMessage
	RemoveCosignerReferenceResultMessage = protocol.RemoveCosignerReferenceResultMessage
	ExportCosignerPublicMessage          = protocol.ExportCosignerPublicMessage
	ExportCosignerPublicResultMessage    = protocol.ExportCosignerPublicResultMessage
	LibraryTemplateInfo                  = protocol.LibraryTemplateInfo
	KeyTypeInfo                          = protocol.KeyTypeInfo
	KeysChangedMessage                   = protocol.KeysChangedMessage
	SignerLockedMessage                  = protocol.SignerLockedMessage
	ClientExistsMessage                  = protocol.ClientExistsMessage
	DisplaceConfirmMessage               = protocol.DisplaceConfirmMessage
	DisplacedMessage                     = protocol.DisplacedMessage
	TokenProvisioningRequestMessage      = protocol.TokenProvisioningRequestMessage
	TokenProvisioningResponseMessage     = protocol.TokenProvisioningResponseMessage
	RevokeTokenMessage                   = protocol.RevokeTokenMessage
	RevokeTokenResultMessage             = protocol.RevokeTokenResultMessage
	GetAdminSettingsMessage              = protocol.GetAdminSettingsMessage
	AdminSettingsMessage                 = protocol.AdminSettingsMessage
	UpdateAdminSettingMessage            = protocol.UpdateAdminSettingMessage
	UpdateAdminSettingResultMessage      = protocol.UpdateAdminSettingResultMessage
	PolicyMessage                        = protocol.PolicyMessage
	PolicyDocumentMessage                = protocol.PolicyDocumentMessage
	CheckPolicyResultMessage             = protocol.CheckPolicyResultMessage
	ApplyPolicyResultMessage             = protocol.ApplyPolicyResultMessage
)

func CurrentAdminProtocolVersion() ProtocolVersion {
	return protocol.CurrentAdminProtocolVersion()
}
