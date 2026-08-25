// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"context"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

type ProductServices interface {
	ProductRuntime() *productruntime.Runtime
	VerifyPassphrase(ir *productruntime.Runtime, passphrase []byte) error
	UnlockIdentity(ir *productruntime.Runtime, passphrase []byte) (bool, int, string, string)
	InitializeStore(req adminproto.InitializeStoreRequest) adminproto.InitializeStoreResult
	ChangeStorePassphrase(ir *productruntime.Runtime, req adminproto.ChangeStorePassphraseRequest) adminproto.ChangeStorePassphraseResult
	NewSessionIdentity(method string) *auth.Identity
	RevokeProductToken(ir *productruntime.Runtime) error
}

type SettingsServices interface {
	BuildAdminSettings(ir *productruntime.Runtime) adminproto.AdminSettings
	UpdateAdminSetting(ir *productruntime.Runtime, req adminproto.UpdateAdminSettingRequest) error
	BuildPolicySnapshot(ir *productruntime.Runtime, target adminproto.PolicyTarget) adminproto.PolicySnapshot
	ReplacePolicy(ir *productruntime.Runtime, req adminproto.ReplacePolicyRequest) adminproto.PolicySnapshot
	ValidatePolicy(ir *productruntime.Runtime, req adminproto.ValidatePolicyRequest) adminproto.ValidatePolicyResult
}

type KeyServices interface {
	ListKeys(ir *productruntime.Runtime) ([]adminproto.KeyInfo, error)
	GetKeyDetails(ir *productruntime.Runtime, req adminproto.GetKeyDetailsRequest) adminproto.GetKeyDetailsResult
	GenerateKey(ctx context.Context, ir *productruntime.Runtime, req adminproto.GenerateKeyRequest) adminproto.GenerateKeyResult
	DeleteKey(ir *productruntime.Runtime, req adminproto.DeleteKeyRequest) adminproto.DeleteKeyResult
	ImportKey(ir *productruntime.Runtime, req adminproto.ImportKeyRequest) adminproto.ImportKeyResult
}

type BackupServices interface {
	BackupIdentity(ir *productruntime.Runtime, req adminproto.BackupIdentityRequest) adminproto.BackupIdentityResult
	ListBackups(ir *productruntime.Runtime) adminproto.ListBackupsResult
	DeleteBackup(ir *productruntime.Runtime, req adminproto.DeleteBackupRequest) adminproto.DeleteBackupResult
	BeginBackupImport(ir *productruntime.Runtime, req adminproto.BeginBackupImportRequest) adminproto.BeginBackupImportResult
	AppendBackupImport(ir *productruntime.Runtime, req adminproto.AppendBackupImportRequest) adminproto.AppendBackupImportResult
	CommitBackupImport(ir *productruntime.Runtime, req adminproto.CommitBackupImportRequest) adminproto.CommitBackupImportResult
	AbortBackupImport(ir *productruntime.Runtime, req adminproto.AbortBackupImportRequest) adminproto.AbortBackupImportResult
	ReadBackupChunk(ir *productruntime.Runtime, req adminproto.ReadBackupChunkRequest) adminproto.ReadBackupChunkResult
	PreviewRestore(ir *productruntime.Runtime, req adminproto.PreviewRestoreRequest) adminproto.RestorePreviewResult
	RestoreBackup(ir *productruntime.Runtime, req adminproto.RestoreBackupRequest) adminproto.RestoreBackupResult
	RollbackRestore(ir *productruntime.Runtime, req adminproto.RollbackRestoreRequest) adminproto.RollbackRestoreResult
	ReconcileStore(ir *productruntime.Runtime) adminproto.ReconcileStoreResult
}

type TemplateServices interface {
	ListLibraryTemplates(ir *productruntime.Runtime) adminproto.ListLibraryTemplatesResult
	InstallLibraryTemplate(ir *productruntime.Runtime, req adminproto.InstallLibraryTemplateRequest) adminproto.InstallLibraryTemplateResult
	ListInstalledTemplates(ir *productruntime.Runtime) adminproto.ListInstalledTemplatesResult
	ShowInstalledTemplate(ir *productruntime.Runtime, req adminproto.ShowInstalledTemplateRequest) adminproto.ShowInstalledTemplateResult
	ShowLibraryTemplate(ir *productruntime.Runtime, req adminproto.ShowLibraryTemplateRequest) adminproto.ShowLibraryTemplateResult
	ImportInstalledTemplate(ir *productruntime.Runtime, req adminproto.ImportInstalledTemplateRequest) adminproto.ImportInstalledTemplateResult
	RemoveInstalledTemplate(ir *productruntime.Runtime, req adminproto.RemoveInstalledTemplateRequest) adminproto.RemoveInstalledTemplateResult
	ActivateKeyType(ir *productruntime.Runtime, req adminproto.ActivateKeyTypeRequest) adminproto.ActivateKeyTypeResult
	DeactivateKeyType(ir *productruntime.Runtime, req adminproto.DeactivateKeyTypeRequest) adminproto.DeactivateKeyTypeResult
	ListKeyTypes(ir *productruntime.Runtime) adminproto.ListKeyTypesResult
}

type StoreInspectionServices interface {
	ListSentryReferences(ir *productruntime.Runtime) adminproto.ListSentryReferencesResult
	GetSentryReference(ir *productruntime.Runtime, req adminproto.GetSentryReferenceRequest) adminproto.GetSentryReferenceResult
	ImportSentryReference(ir *productruntime.Runtime, req adminproto.ImportSentryReferenceRequest) adminproto.ImportSentryReferenceResult
	RemoveSentryReference(ir *productruntime.Runtime, req adminproto.RemoveSentryReferenceRequest) adminproto.RemoveSentryReferenceResult
	ExportSentryPublic(ir *productruntime.Runtime, req adminproto.ExportSentryPublicRequest) adminproto.ExportSentryPublicResult
	ListGenerations(ir *productruntime.Runtime) adminproto.GenerationInventory
}

type AuthorizationAudit interface {
	LogAuthorizationDenied(ctx SessionContext, action auth.Action, resource auth.Resource, reason string)
}

type SessionDeps struct {
	Product     ProductServices
	Settings    SettingsServices
	Keys        KeyServices
	Backups     BackupServices
	Templates   TemplateServices
	Inspection  StoreInspectionServices
	Authorizer  auth.Authorizer
	Audit       AuthorizationAudit
	NodeFailure func() error
}
