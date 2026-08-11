// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"context"
	"github.com/aplane-algo/aplane/internal/adminproto"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

type IdentityServices interface {
	ProductIdentityRuntime() *identity.Runtime
	ResolveIdentity(identityID string) (*identity.Runtime, error)
	VerifyPassphrase(ir *identity.Runtime, passphrase []byte) error
	UnlockIdentity(ir *identity.Runtime, passphrase []byte) (bool, int, string, string)
	InitializeStore(req adminproto.InitializeStoreRequest) adminproto.InitializeStoreResult
	ChangeStorePassphrase(ir *identity.Runtime, req adminproto.ChangeStorePassphraseRequest) adminproto.ChangeStorePassphraseResult
	NewSessionIdentity(method string) *auth.Identity
	RevokeTokenForIdentity(ir *identity.Runtime) error
}

type SettingsServices interface {
	BuildAdminSettings(ir *identity.Runtime) adminproto.AdminSettings
	UpdateAdminSetting(ir *identity.Runtime, req adminproto.UpdateAdminSettingRequest) error
	BuildPolicySnapshot(ir *identity.Runtime, target adminproto.PolicyTarget) adminproto.PolicySnapshot
	ReplacePolicy(ir *identity.Runtime, req adminproto.ReplacePolicyRequest) adminproto.PolicySnapshot
	ValidatePolicy(ir *identity.Runtime, req adminproto.ValidatePolicyRequest) adminproto.ValidatePolicyResult
}

type KeyServices interface {
	ListKeys(ir *identity.Runtime) ([]adminproto.KeyInfo, error)
	GetKeyDetails(ir *identity.Runtime, req adminproto.GetKeyDetailsRequest) adminproto.GetKeyDetailsResult
	GenerateKey(ctx context.Context, ir *identity.Runtime, req adminproto.GenerateKeyRequest) adminproto.GenerateKeyResult
	DeleteKey(ir *identity.Runtime, req adminproto.DeleteKeyRequest) adminproto.DeleteKeyResult
	ImportKey(ir *identity.Runtime, req adminproto.ImportKeyRequest) adminproto.ImportKeyResult
}

type BackupServices interface {
	BackupIdentity(ir *identity.Runtime, req adminproto.BackupIdentityRequest) adminproto.BackupIdentityResult
	ListBackups(ir *identity.Runtime) adminproto.ListBackupsResult
	DeleteBackup(ir *identity.Runtime, req adminproto.DeleteBackupRequest) adminproto.DeleteBackupResult
	BeginBackupImport(ir *identity.Runtime, req adminproto.BeginBackupImportRequest) adminproto.BeginBackupImportResult
	AppendBackupImport(ir *identity.Runtime, req adminproto.AppendBackupImportRequest) adminproto.AppendBackupImportResult
	CommitBackupImport(ir *identity.Runtime, req adminproto.CommitBackupImportRequest) adminproto.CommitBackupImportResult
	AbortBackupImport(ir *identity.Runtime, req adminproto.AbortBackupImportRequest) adminproto.AbortBackupImportResult
	ReadBackupChunk(ir *identity.Runtime, req adminproto.ReadBackupChunkRequest) adminproto.ReadBackupChunkResult
	PreviewRestore(ir *identity.Runtime, req adminproto.PreviewRestoreRequest) adminproto.RestorePreviewResult
	RestoreBackup(ir *identity.Runtime, req adminproto.RestoreBackupRequest) adminproto.RestoreBackupResult
	RollbackRestore(ir *identity.Runtime, req adminproto.RollbackRestoreRequest) adminproto.RollbackRestoreResult
	ReconcileStore(ir *identity.Runtime) adminproto.ReconcileStoreResult
}

type TemplateServices interface {
	ListLibraryTemplates(ir *identity.Runtime) adminproto.ListLibraryTemplatesResult
	InstallLibraryTemplate(ir *identity.Runtime, req adminproto.InstallLibraryTemplateRequest) adminproto.InstallLibraryTemplateResult
	ListInstalledTemplates(ir *identity.Runtime) adminproto.ListInstalledTemplatesResult
	ShowInstalledTemplate(ir *identity.Runtime, req adminproto.ShowInstalledTemplateRequest) adminproto.ShowInstalledTemplateResult
	ShowLibraryTemplate(ir *identity.Runtime, req adminproto.ShowLibraryTemplateRequest) adminproto.ShowLibraryTemplateResult
	ImportInstalledTemplate(ir *identity.Runtime, req adminproto.ImportInstalledTemplateRequest) adminproto.ImportInstalledTemplateResult
	RemoveInstalledTemplate(ir *identity.Runtime, req adminproto.RemoveInstalledTemplateRequest) adminproto.RemoveInstalledTemplateResult
	ActivateKeyType(ir *identity.Runtime, req adminproto.ActivateKeyTypeRequest) adminproto.ActivateKeyTypeResult
	DeactivateKeyType(ir *identity.Runtime, req adminproto.DeactivateKeyTypeRequest) adminproto.DeactivateKeyTypeResult
	ListKeyTypes(ir *identity.Runtime) adminproto.ListKeyTypesResult
}

type StoreInspectionServices interface {
	ListSentryReferences(ir *identity.Runtime) adminproto.ListSentryReferencesResult
	GetSentryReference(ir *identity.Runtime, req adminproto.GetSentryReferenceRequest) adminproto.GetSentryReferenceResult
	ImportSentryReference(ir *identity.Runtime, req adminproto.ImportSentryReferenceRequest) adminproto.ImportSentryReferenceResult
	RemoveSentryReference(ir *identity.Runtime, req adminproto.RemoveSentryReferenceRequest) adminproto.RemoveSentryReferenceResult
	ExportSentryPublic(ir *identity.Runtime, req adminproto.ExportSentryPublicRequest) adminproto.ExportSentryPublicResult
	ListGenerations(ir *identity.Runtime) adminproto.GenerationInventory
}

type AuthorizationAudit interface {
	LogAuthorizationDenied(ctx SessionContext, action auth.Action, resource auth.Resource, reason string)
}

type SessionDeps struct {
	Identity   IdentityServices
	Settings   SettingsServices
	Keys       KeyServices
	Backups    BackupServices
	Templates  TemplateServices
	Inspection StoreInspectionServices
	Authorizer auth.Authorizer
	Audit      AuthorizationAudit
}
