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
	VerifyPassphrase(passphrase []byte) error
	UnlockIdentity(passphrase []byte) (bool, int, string, string)
	InitializeStore(req adminproto.InitializeStoreRequest) adminproto.InitializeStoreResult
	ChangeStorePassphrase(req adminproto.ChangeStorePassphraseRequest) adminproto.ChangeStorePassphraseResult
	NewSessionIdentity(method string) *auth.Identity
	RevokeProductToken() error
}

type SettingsServices interface {
	BuildAdminSettings() adminproto.AdminSettings
	UpdateAdminSetting(req adminproto.UpdateAdminSettingRequest) error
	BuildPolicySnapshot(target adminproto.PolicyTarget) adminproto.PolicySnapshot
	ReplacePolicy(req adminproto.ReplacePolicyRequest) adminproto.PolicySnapshot
	ValidatePolicy(req adminproto.ValidatePolicyRequest) adminproto.ValidatePolicyResult
}

type KeyServices interface {
	ListKeys() ([]adminproto.KeyInfo, error)
	GetKeyDetails(req adminproto.GetKeyDetailsRequest) adminproto.GetKeyDetailsResult
	GenerateKey(ctx context.Context, req adminproto.GenerateKeyRequest) adminproto.GenerateKeyResult
	DeleteKey(req adminproto.DeleteKeyRequest) adminproto.DeleteKeyResult
	ImportKey(req adminproto.ImportKeyRequest) adminproto.ImportKeyResult
}

type BackupServices interface {
	BackupIdentity(req adminproto.BackupIdentityRequest) adminproto.BackupIdentityResult
	ListBackups() adminproto.ListBackupsResult
	DeleteBackup(req adminproto.DeleteBackupRequest) adminproto.DeleteBackupResult
	BeginBackupImport(req adminproto.BeginBackupImportRequest) adminproto.BeginBackupImportResult
	AppendBackupImport(req adminproto.AppendBackupImportRequest) adminproto.AppendBackupImportResult
	CommitBackupImport(req adminproto.CommitBackupImportRequest) adminproto.CommitBackupImportResult
	AbortBackupImport(req adminproto.AbortBackupImportRequest) adminproto.AbortBackupImportResult
	ReadBackupChunk(req adminproto.ReadBackupChunkRequest) adminproto.ReadBackupChunkResult
	PreviewRestore(req adminproto.PreviewRestoreRequest) adminproto.RestorePreviewResult
	RestoreBackup(req adminproto.RestoreBackupRequest) adminproto.RestoreBackupResult
	RollbackRestore(req adminproto.RollbackRestoreRequest) adminproto.RollbackRestoreResult
	ReconcileStore() adminproto.ReconcileStoreResult
}

type TemplateServices interface {
	ListLibraryTemplates() adminproto.ListLibraryTemplatesResult
	InstallLibraryTemplate(req adminproto.InstallLibraryTemplateRequest) adminproto.InstallLibraryTemplateResult
	ListInstalledTemplates() adminproto.ListInstalledTemplatesResult
	ShowInstalledTemplate(req adminproto.ShowInstalledTemplateRequest) adminproto.ShowInstalledTemplateResult
	ShowLibraryTemplate(req adminproto.ShowLibraryTemplateRequest) adminproto.ShowLibraryTemplateResult
	ImportInstalledTemplate(req adminproto.ImportInstalledTemplateRequest) adminproto.ImportInstalledTemplateResult
	RemoveInstalledTemplate(req adminproto.RemoveInstalledTemplateRequest) adminproto.RemoveInstalledTemplateResult
	ActivateKeyType(req adminproto.ActivateKeyTypeRequest) adminproto.ActivateKeyTypeResult
	DeactivateKeyType(req adminproto.DeactivateKeyTypeRequest) adminproto.DeactivateKeyTypeResult
	ListKeyTypes() adminproto.ListKeyTypesResult
}

type StoreInspectionServices interface {
	ListSentryReferences() adminproto.ListSentryReferencesResult
	GetSentryReference(req adminproto.GetSentryReferenceRequest) adminproto.GetSentryReferenceResult
	ImportSentryReference(req adminproto.ImportSentryReferenceRequest) adminproto.ImportSentryReferenceResult
	RemoveSentryReference(req adminproto.RemoveSentryReferenceRequest) adminproto.RemoveSentryReferenceResult
	ExportSentryPublic(req adminproto.ExportSentryPublicRequest) adminproto.ExportSentryPublicResult
	ListGenerations() adminproto.GenerationInventory
	PruneGenerationQuarantine(req adminproto.PruneGenerationQuarantineRequest) adminproto.PruneGenerationQuarantineResult
	ListDeletedArchive() adminproto.DeletedArchiveInventory
	PruneDeletedArchive(req adminproto.PruneDeletedArchiveRequest) adminproto.PruneDeletedArchiveResult
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
