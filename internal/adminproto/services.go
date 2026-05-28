// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"context"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

type IdentityServices interface {
	ProductIdentityRuntime() *identity.Runtime
	ResolveIdentity(identityID string) (*identity.Runtime, error)
	VerifyPassphrase(ir *identity.Runtime, passphrase []byte) error
	UnlockIdentity(ir *identity.Runtime, passphrase []byte) (bool, int, string)
	InitializeStore(req InitializeStoreRequest) InitializeStoreResult
	ChangeStorePassphrase(ir *identity.Runtime, req ChangeStorePassphraseRequest) ChangeStorePassphraseResult
	NewSessionIdentity(method string) *auth.Identity
	RevokeTokenForIdentity(ir *identity.Runtime) error
}

type SettingsServices interface {
	BuildAdminSettings(ir *identity.Runtime) AdminSettings
	UpdateAdminSetting(ir *identity.Runtime, req UpdateAdminSettingRequest) error
	BuildPolicySettings(ir *identity.Runtime) PolicySettings
	BuildPolicySnapshot(ir *identity.Runtime) PolicySnapshot
	ReplacePolicy(ir *identity.Runtime, req ReplacePolicyRequest) PolicySnapshot
	UpdatePolicySetting(ir *identity.Runtime, req UpdatePolicySettingRequest) error
	UpdatePolicyASAAmounts(ir *identity.Runtime, req UpdatePolicyASAAmountsRequest) error
	SearchASAMetadata(ir *identity.Runtime, req SearchASAMetadataRequest) ASAMetadataResults
	ResolveASAMetadata(ir *identity.Runtime, req ResolveASAMetadataRequest) ASAMetadataResult
}

type KeyServices interface {
	ListKeys(ir *identity.Runtime) ([]KeyInfo, error)
	GetKeyDetails(ir *identity.Runtime, req GetKeyDetailsRequest) GetKeyDetailsResult
	GenerateKey(ctx context.Context, ir *identity.Runtime, req GenerateKeyRequest) GenerateKeyResult
	DeleteKey(ir *identity.Runtime, req DeleteKeyRequest) DeleteKeyResult
	ImportKey(ir *identity.Runtime, req ImportKeyRequest) ImportKeyResult
}

type BackupServices interface {
	BackupIdentity(ir *identity.Runtime, req BackupIdentityRequest) BackupIdentityResult
	ListBackups(ir *identity.Runtime) ListBackupsResult
	DeleteBackup(ir *identity.Runtime, req DeleteBackupRequest) DeleteBackupResult
	PreviewRestore(ir *identity.Runtime, req PreviewRestoreRequest) RestorePreviewResult
	RestoreBackup(ir *identity.Runtime, req RestoreBackupRequest) RestoreBackupResult
}

type TemplateServices interface {
	ListLibraryTemplates(ir *identity.Runtime) ListLibraryTemplatesResult
	InstallLibraryTemplate(ir *identity.Runtime, req InstallLibraryTemplateRequest) InstallLibraryTemplateResult
	ListInstalledTemplates(ir *identity.Runtime) ListInstalledTemplatesResult
	ShowInstalledTemplate(ir *identity.Runtime, req ShowInstalledTemplateRequest) ShowInstalledTemplateResult
	ShowLibraryTemplate(ir *identity.Runtime, req ShowLibraryTemplateRequest) ShowLibraryTemplateResult
	ImportInstalledTemplate(ir *identity.Runtime, req ImportInstalledTemplateRequest) ImportInstalledTemplateResult
	RemoveInstalledTemplate(ir *identity.Runtime, req RemoveInstalledTemplateRequest) RemoveInstalledTemplateResult
	ActivateKeyType(ir *identity.Runtime, req ActivateKeyTypeRequest) ActivateKeyTypeResult
	DeactivateKeyType(ir *identity.Runtime, req DeactivateKeyTypeRequest) DeactivateKeyTypeResult
	ListKeyTypes(ir *identity.Runtime) ListKeyTypesResult
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
