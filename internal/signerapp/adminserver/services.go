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
	BuildPolicySettings(ir *identity.Runtime) adminproto.PolicySettings
	BuildPolicySnapshot(ir *identity.Runtime, target adminproto.PolicyTarget) adminproto.PolicySnapshot
	ReplacePolicy(ir *identity.Runtime, req adminproto.ReplacePolicyRequest) adminproto.PolicySnapshot
	ValidatePolicy(ir *identity.Runtime, req adminproto.ValidatePolicyRequest) adminproto.ValidatePolicyResult
	UpdatePolicySetting(ir *identity.Runtime, req adminproto.UpdatePolicySettingRequest) error
	UpdatePolicyASAAmounts(ir *identity.Runtime, req adminproto.UpdatePolicyASAAmountsRequest) error
	SearchASAMetadata(ir *identity.Runtime, req adminproto.SearchASAMetadataRequest) adminproto.ASAMetadataResults
	ResolveASAMetadata(ir *identity.Runtime, req adminproto.ResolveASAMetadataRequest) adminproto.ASAMetadataResult
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
	PreviewRestore(ir *identity.Runtime, req adminproto.PreviewRestoreRequest) adminproto.RestorePreviewResult
	RestoreBackup(ir *identity.Runtime, req adminproto.RestoreBackupRequest) adminproto.RestoreBackupResult
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

type AuthorizationAudit interface {
	LogAuthorizationDenied(ctx SessionContext, action auth.Action, resource auth.Resource, reason string)
}

type SessionDeps struct {
	Identity   IdentityServices
	Settings   SettingsServices
	Keys       KeyServices
	Backups    BackupServices
	Templates  TemplateServices
	Authorizer auth.Authorizer
	Audit      AuthorizationAudit
}
