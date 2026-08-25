// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"

	"github.com/aplane-algo/aplane/internal/adminproto"
	signeradmin "github.com/aplane-algo/aplane/internal/signerapp/admin"
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

// The admin protocol services are bound to the signer's one product runtime.
// These adapters keep that ownership at assembly time instead of threading a
// selector-shaped runtime argument through every session dispatch.

type signerSettingsServices struct {
	service signeradmin.Service
	daemon  signerAdminServices
}

func (s signerSettingsServices) BuildAdminSettings() adminproto.AdminSettings {
	return s.service.BuildAdminSettings(s.daemon.runtime())
}

func (s signerSettingsServices) UpdateAdminSetting(req adminproto.UpdateAdminSettingRequest) error {
	return s.service.UpdateAdminSetting(s.daemon.runtime(), req)
}

func (s signerSettingsServices) BuildPolicySnapshot(target adminproto.PolicyTarget) adminproto.PolicySnapshot {
	return s.service.BuildPolicySnapshot(s.daemon.runtime(), target)
}

func (s signerSettingsServices) ReplacePolicy(req adminproto.ReplacePolicyRequest) adminproto.PolicySnapshot {
	return s.service.ReplacePolicy(s.daemon.runtime(), req)
}

func (s signerSettingsServices) ValidatePolicy(req adminproto.ValidatePolicyRequest) adminproto.ValidatePolicyResult {
	return s.service.ValidatePolicy(s.daemon.runtime(), req)
}

type signerKeyServices struct {
	service keyadmin.IPCService
	daemon  signerAdminServices
}

func (s signerKeyServices) ListKeys() ([]adminproto.KeyInfo, error) {
	return s.service.ListKeys(s.daemon.runtime())
}

func (s signerKeyServices) GetKeyDetails(req adminproto.GetKeyDetailsRequest) adminproto.GetKeyDetailsResult {
	return s.service.GetKeyDetails(s.daemon.runtime(), req)
}

func (s signerKeyServices) GenerateKey(ctx context.Context, req adminproto.GenerateKeyRequest) adminproto.GenerateKeyResult {
	return s.service.GenerateKey(ctx, s.daemon.runtime(), req)
}

func (s signerKeyServices) DeleteKey(req adminproto.DeleteKeyRequest) adminproto.DeleteKeyResult {
	return s.service.DeleteKey(s.daemon.runtime(), req)
}

func (s signerKeyServices) ImportKey(req adminproto.ImportKeyRequest) adminproto.ImportKeyResult {
	return s.service.ImportKey(s.daemon.runtime(), req)
}

func (s signerBackupServices) BackupIdentity(req adminproto.BackupIdentityRequest) adminproto.BackupIdentityResult {
	return s.Service.BackupIdentity(s.daemon.runtime(), req)
}

func (s signerBackupServices) ListBackups() adminproto.ListBackupsResult {
	return s.Service.ListBackups(s.daemon.runtime())
}

func (s signerBackupServices) DeleteBackup(req adminproto.DeleteBackupRequest) adminproto.DeleteBackupResult {
	return s.Service.DeleteBackup(s.daemon.runtime(), req)
}

func (s signerBackupServices) BeginBackupImport(req adminproto.BeginBackupImportRequest) adminproto.BeginBackupImportResult {
	return s.Service.BeginBackupImport(req)
}

func (s signerBackupServices) AppendBackupImport(req adminproto.AppendBackupImportRequest) adminproto.AppendBackupImportResult {
	return s.Service.AppendBackupImport(req)
}

func (s signerBackupServices) CommitBackupImport(req adminproto.CommitBackupImportRequest) adminproto.CommitBackupImportResult {
	return s.Service.CommitBackupImport(req)
}

func (s signerBackupServices) AbortBackupImport(req adminproto.AbortBackupImportRequest) adminproto.AbortBackupImportResult {
	return s.Service.AbortBackupImport(req)
}

func (s signerBackupServices) ReadBackupChunk(req adminproto.ReadBackupChunkRequest) adminproto.ReadBackupChunkResult {
	return s.Service.ReadBackupChunk(req)
}

func (s signerBackupServices) PreviewRestore(req adminproto.PreviewRestoreRequest) adminproto.RestorePreviewResult {
	return s.Service.PreviewRestore(s.daemon.runtime(), req)
}

func (s signerTemplateServices) ListLibraryTemplates() adminproto.ListLibraryTemplatesResult {
	return s.Service.ListLibraryTemplates()
}

func (s signerTemplateServices) InstallLibraryTemplate(req adminproto.InstallLibraryTemplateRequest) adminproto.InstallLibraryTemplateResult {
	return s.Service.InstallLibraryTemplate(s.runtime(), req)
}

func (s signerTemplateServices) ListInstalledTemplates() adminproto.ListInstalledTemplatesResult {
	return s.Service.ListInstalledTemplates()
}

func (s signerTemplateServices) ShowInstalledTemplate(req adminproto.ShowInstalledTemplateRequest) adminproto.ShowInstalledTemplateResult {
	return s.Service.ShowInstalledTemplate(s.runtime(), req)
}

func (s signerTemplateServices) ShowLibraryTemplate(req adminproto.ShowLibraryTemplateRequest) adminproto.ShowLibraryTemplateResult {
	return s.Service.ShowLibraryTemplate(req)
}

func (s signerTemplateServices) ImportInstalledTemplate(req adminproto.ImportInstalledTemplateRequest) adminproto.ImportInstalledTemplateResult {
	return s.Service.ImportInstalledTemplate(s.runtime(), req)
}

func (s signerTemplateServices) RemoveInstalledTemplate(req adminproto.RemoveInstalledTemplateRequest) adminproto.RemoveInstalledTemplateResult {
	return s.Service.RemoveInstalledTemplate(s.runtime(), req)
}

func (s signerTemplateServices) ActivateKeyType(req adminproto.ActivateKeyTypeRequest) adminproto.ActivateKeyTypeResult {
	return s.Service.ActivateKeyType(s.runtime(), req)
}

func (s signerTemplateServices) DeactivateKeyType(req adminproto.DeactivateKeyTypeRequest) adminproto.DeactivateKeyTypeResult {
	return s.Service.DeactivateKeyType(s.runtime(), req)
}

func (s signerTemplateServices) runtime() *productruntime.Runtime {
	return s.signer.productRuntime()
}
