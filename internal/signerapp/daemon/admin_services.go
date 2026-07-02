// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/authz"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
	signeradmin "github.com/aplane-algo/aplane/internal/signerapp/admin"
	"github.com/aplane-algo/aplane/internal/signerapp/backupadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/storeadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/templateadmin"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type signerAdminServices struct {
	signer *Signer
}

type signerAdminAppDeps struct {
	signer *Signer
}

func (fs *Signer) adminServices() signerAdminServices {
	return signerAdminServices{signer: fs}
}

func (fs *Signer) adminSessionDeps() adminserver.SessionDeps {
	if fs == nil {
		return adminserver.SessionDeps{}
	}
	svc := fs.adminServices()
	return adminserver.SessionDeps{
		Identity:   svc,
		Settings:   svc,
		Keys:       svc,
		Backups:    svc,
		Templates:  svc,
		Authorizer: fs.authorizer,
		Audit:      svc,
	}
}

func (s signerAdminServices) ProductIdentityRuntime() *identity.Runtime {
	return s.signer.productIdentityRuntime()
}

func (s signerAdminServices) ResolveIdentity(identityID string) (*identity.Runtime, error) {
	if err := s.signer.registry.CloseError(); err != nil {
		return nil, err
	}
	targetIdentityID := identityID
	if targetIdentityID == "" {
		targetIdentityID = auth.CurrentProductIdentityID()
	}
	// Product-mode admin restrictions live in adminproto.Session's auth
	// reconciliation. This resolver stays registry-scoped so SSH-prebound
	// sessions can resolve the identity authenticated by the SSH layer.
	ir := s.signer.registry.Get(targetIdentityID)
	if ir == nil {
		return nil, fmt.Errorf("identity not available: %s", targetIdentityID)
	}
	return ir, nil
}

func (s signerAdminServices) VerifyPassphrase(ir *identity.Runtime, passphrase []byte) error {
	return crypto.VerifyPassphraseWithMetadata(passphrase, ir.KeyPaths().KeystoreMetadataDir(ir.ID()))
}

func (s signerAdminServices) UnlockIdentity(ir *identity.Runtime, passphrase []byte) (bool, int, string, string) {
	success, keyCount, errMsg := ir.TryUnlock(passphrase, func() {
		ir.EnsureKeyWatcher(startKeyWatcherForDir)
	})
	return success, keyCount, errMsg, unlockFailureCode(errMsg)
}

func unlockFailureCode(errMsg string) string {
	switch {
	case errMsg == "":
		return ""
	case errMsg == "invalid passphrase":
		return protocol.ErrCodeInvalidPassphrase
	case strings.HasPrefix(errMsg, "failed to load keys:"):
		return protocol.ErrCodeUnlockFailed
	default:
		return protocol.ErrCodeUnlockFailed
	}
}

func (s signerAdminServices) InitializeStore(req adminproto.InitializeStoreRequest) adminproto.InitializeStoreResult {
	return s.storeApp().InitializeStore(s.ProductIdentityRuntime(), req)
}

func (s signerAdminServices) ChangeStorePassphrase(ir *identity.Runtime, req adminproto.ChangeStorePassphraseRequest) adminproto.ChangeStorePassphraseResult {
	return s.storeApp().ChangeStorePassphrase(ir, req)
}

func (s signerAdminServices) NewSessionIdentity(method string) *auth.Identity {
	return authz.NewProductPrincipalIdentity(method)
}

func (s signerAdminServices) LogAuthorizationDenied(ctx adminserver.SessionContext, action auth.Action, resource auth.Resource, reason string) {
	if s.signer == nil || s.signer.auditLog == nil {
		return
	}
	s.signer.auditLog.LogAuthorizationDenied(ctx, action, resource, reason)
}

func (s signerAdminServices) RevokeTokenForIdentity(ir *identity.Runtime) error {
	return s.signer.RevokeTokenForIdentity(ir)
}

func (s signerAdminServices) BuildAdminSettings(ir *identity.Runtime) adminproto.AdminSettings {
	return s.adminApp().BuildAdminSettings(ir)
}

func (s signerAdminServices) UpdateAdminSetting(ir *identity.Runtime, req adminproto.UpdateAdminSettingRequest) error {
	return s.adminApp().UpdateAdminSetting(ir, req)
}

func (s signerAdminServices) BuildPolicySettings(ir *identity.Runtime) adminproto.PolicySettings {
	return s.adminApp().BuildPolicySettings(ir)
}

func (s signerAdminServices) BuildPolicySnapshot(ir *identity.Runtime, target adminproto.PolicyTarget) adminproto.PolicySnapshot {
	return s.adminApp().BuildPolicySnapshot(ir, target)
}

func (s signerAdminServices) ReplacePolicy(ir *identity.Runtime, req adminproto.ReplacePolicyRequest) adminproto.PolicySnapshot {
	return s.adminApp().ReplacePolicy(ir, req)
}

func (s signerAdminServices) ValidatePolicy(ir *identity.Runtime, req adminproto.ValidatePolicyRequest) adminproto.ValidatePolicyResult {
	return s.adminApp().ValidatePolicy(ir, req)
}

func (s signerAdminServices) UpdatePolicySetting(ir *identity.Runtime, req adminproto.UpdatePolicySettingRequest) error {
	return s.adminApp().UpdatePolicySetting(ir, req)
}

func (s signerAdminServices) UpdatePolicyASAAmounts(ir *identity.Runtime, req adminproto.UpdatePolicyASAAmountsRequest) error {
	return s.adminApp().UpdatePolicyASAAmounts(ir, req)
}

func (s signerAdminServices) SearchASAMetadata(ir *identity.Runtime, req adminproto.SearchASAMetadataRequest) adminproto.ASAMetadataResults {
	return s.adminApp().SearchASAMetadata(ir, req)
}

func (s signerAdminServices) ResolveASAMetadata(ir *identity.Runtime, req adminproto.ResolveASAMetadataRequest) adminproto.ASAMetadataResult {
	return s.adminApp().ResolveASAMetadata(ir, req)
}

func (s signerAdminServices) ListKeys(ir *identity.Runtime) ([]adminproto.KeyInfo, error) {
	return s.keyApp().ListKeys(ir)
}

func (s signerAdminServices) GetKeyDetails(ir *identity.Runtime, req adminproto.GetKeyDetailsRequest) adminproto.GetKeyDetailsResult {
	return s.keyApp().GetKeyDetails(ir, req)
}

func (s signerAdminServices) GenerateKey(ctx context.Context, ir *identity.Runtime, req adminproto.GenerateKeyRequest) adminproto.GenerateKeyResult {
	return s.keyApp().GenerateKey(ctx, ir, req)
}

func (s signerAdminServices) DeleteKey(ir *identity.Runtime, req adminproto.DeleteKeyRequest) adminproto.DeleteKeyResult {
	return s.keyApp().DeleteKey(ir, req)
}

func (s signerAdminServices) ImportKey(ir *identity.Runtime, req adminproto.ImportKeyRequest) adminproto.ImportKeyResult {
	return s.keyApp().ImportKey(ir, req)
}

func (s signerAdminServices) BackupIdentity(ir *identity.Runtime, req adminproto.BackupIdentityRequest) adminproto.BackupIdentityResult {
	return s.backupApp().BackupIdentity(ir, req)
}

func (s signerAdminServices) ListBackups(ir *identity.Runtime) adminproto.ListBackupsResult {
	return s.backupApp().ListBackups(ir)
}

func (s signerAdminServices) DeleteBackup(ir *identity.Runtime, req adminproto.DeleteBackupRequest) adminproto.DeleteBackupResult {
	return s.backupApp().DeleteBackup(ir, req)
}

func (s signerAdminServices) PreviewRestore(ir *identity.Runtime, req adminproto.PreviewRestoreRequest) adminproto.RestorePreviewResult {
	return s.backupApp().PreviewRestore(ir, req)
}

func (s signerAdminServices) RestoreBackup(ir *identity.Runtime, req adminproto.RestoreBackupRequest) adminproto.RestoreBackupResult {
	return s.backupApp().RestoreBackup(ir, req)
}

func (s signerAdminServices) ListLibraryTemplates(ir *identity.Runtime) adminproto.ListLibraryTemplatesResult {
	return s.templateApp().ListLibraryTemplates(ir)
}

func (s signerAdminServices) InstallLibraryTemplate(ir *identity.Runtime, req adminproto.InstallLibraryTemplateRequest) adminproto.InstallLibraryTemplateResult {
	return s.templateApp().InstallLibraryTemplate(ir, req)
}

func (s signerAdminServices) ListInstalledTemplates(ir *identity.Runtime) adminproto.ListInstalledTemplatesResult {
	return s.templateApp().ListInstalledTemplates(ir)
}

func (s signerAdminServices) ShowInstalledTemplate(ir *identity.Runtime, req adminproto.ShowInstalledTemplateRequest) adminproto.ShowInstalledTemplateResult {
	return s.templateApp().ShowInstalledTemplate(ir, req)
}

func (s signerAdminServices) ShowLibraryTemplate(ir *identity.Runtime, req adminproto.ShowLibraryTemplateRequest) adminproto.ShowLibraryTemplateResult {
	return s.templateApp().ShowLibraryTemplate(ir, req)
}

func (s signerAdminServices) ImportInstalledTemplate(ir *identity.Runtime, req adminproto.ImportInstalledTemplateRequest) adminproto.ImportInstalledTemplateResult {
	return s.templateApp().ImportInstalledTemplate(ir, req)
}

func (s signerAdminServices) RemoveInstalledTemplate(ir *identity.Runtime, req adminproto.RemoveInstalledTemplateRequest) adminproto.RemoveInstalledTemplateResult {
	return s.templateApp().RemoveInstalledTemplate(ir, req)
}

func (s signerAdminServices) ActivateKeyType(ir *identity.Runtime, req adminproto.ActivateKeyTypeRequest) adminproto.ActivateKeyTypeResult {
	return s.templateApp().ActivateKeyType(ir, req)
}

func (s signerAdminServices) DeactivateKeyType(ir *identity.Runtime, req adminproto.DeactivateKeyTypeRequest) adminproto.DeactivateKeyTypeResult {
	return s.templateApp().DeactivateKeyType(ir, req)
}

func (s signerAdminServices) ListKeyTypes(ir *identity.Runtime) adminproto.ListKeyTypesResult {
	resp, err := s.signer.restService().KeyTypesForIdentity(ir)
	if err != nil {
		return adminproto.ListKeyTypesResult{
			Code:  "list_failed",
			Error: err.Error(),
		}
	}
	if resp == nil {
		return adminproto.ListKeyTypesResult{KeyTypes: nil}
	}
	return adminproto.ListKeyTypesResult{KeyTypes: resp.KeyTypes}
}

func (s signerAdminServices) Theme() string {
	return s.signer.Theme()
}

func (s signerAdminServices) SetTheme(v string) {
	s.signer.SetTheme(v)
}

func (s signerAdminServices) Config() *serverconfig.ServerConfig {
	cfg := s.signer.ConfigSnapshot()
	return &cfg
}

func (s signerAdminServices) DataDir() string {
	return s.signer.dataDir
}

func (s signerAdminServices) KeyPaths() storepaths.Paths {
	return s.signer.keyPaths
}

func (s signerAdminServices) SSHEnabled() bool {
	return s.signer.currentSSHServer() != nil
}

func (s signerAdminServices) SSHPort() int {
	return s.signer.ConfigSnapshot().Endpoint.SSH.Port
}

func (s signerAdminServices) SSHClients() int {
	sshServer := s.signer.currentSSHServer()
	if sshServer == nil {
		return 0
	}
	return sshServer.ActiveConnectionCount()
}

func (s signerAdminServices) SSHFingerprint() string {
	sshServer := s.signer.currentSSHServer()
	if sshServer == nil {
		return ""
	}
	return sshServer.GetHostKeyFingerprint()
}

func (s signerAdminServices) LogSessionConnected(identityID, remoteAddr, transport string) {
	if s.signer.auditLog != nil {
		s.signer.auditLog.LogSessionConnected(identityID, remoteAddr, transport)
	}
}

func (s signerAdminServices) LogSessionDisconnected(identityID, remoteAddr, transport string) {
	if s.signer.auditLog != nil {
		s.signer.auditLog.LogSessionDisconnected(identityID, remoteAddr, transport)
	}
}

func (s signerAdminServices) LogSessionConnectedContext(ctx adminserver.SessionContext) {
	if s.signer.auditLog != nil {
		s.signer.auditLog.LogSessionConnectedContext(ctx)
	}
}

func (s signerAdminServices) LogSessionDisconnectedContext(ctx adminserver.SessionContext) {
	if s.signer.auditLog != nil {
		s.signer.auditLog.LogSessionDisconnectedContext(ctx)
	}
}

func (s signerAdminServices) adminApp() signeradmin.Service {
	return signeradmin.Service{Deps: signerAdminAppDeps(s)}
}

func (s signerAdminServices) backupApp() backupadmin.Service {
	return backupadmin.Service{Deps: signerAdminAppDeps(s)}
}

func (s signerAdminServices) templateApp() templateadmin.Service {
	return templateadmin.Service{Deps: signerAdminAppDeps(s)}
}

func (s signerAdminServices) storeApp() storeadmin.Service {
	return storeadmin.Service{
		Deps:           signerAdminAppDeps(s),
		AuditLog:       s.signer.auditLog,
		UnlockIdentity: s.UnlockIdentity,
	}
}

func (s signerAdminServices) keyApp() keyadmin.IPCService {
	return keyadmin.IPCService{
		Service:             s.signer.restService().Deps.KeyAdmin,
		GenerateGenericLSig: s.signer.generateGenericLSigForIdentityContext,
		Logf:                logInfof,
	}
}

func (d signerAdminAppDeps) DataDir() string {
	return d.signer.dataDir
}

func (d signerAdminAppDeps) Config() *serverconfig.ServerConfig {
	cfg := d.signer.ConfigSnapshot()
	return &cfg
}

func (d signerAdminAppDeps) KeyPaths() storepaths.Paths {
	return d.signer.keyPaths
}

func (d signerAdminAppDeps) Theme() string {
	return d.signer.Theme()
}

func (d signerAdminAppDeps) SetTheme(v string) {
	d.signer.SetTheme(v)
}

func (d signerAdminAppDeps) SSHInfo() signeradmin.SSHInfo {
	cfg := d.signer.ConfigSnapshot()
	sshServer := d.signer.currentSSHServer()
	info := signeradmin.SSHInfo{
		Enabled: sshServer != nil,
		Port:    cfg.Endpoint.SSH.Port,
	}
	if sshServer != nil {
		info.Clients = sshServer.ActiveConnectionCount()
		info.Fingerprint = sshServer.GetHostKeyFingerprint()
	}
	return info
}

func (d signerAdminAppDeps) WithProcessConfigMutation(fn func() error) error {
	return d.signer.withProcessConfigMutation(fn)
}

func (d signerAdminAppDeps) WithIdentityMutation(identityID string, fn func() error) error {
	return d.signer.withIdentityMutation(identityID, fn)
}

func (d signerAdminAppDeps) RestoreLimiter() backupadmin.RestoreLimiter {
	return d.signer.restoreAttemptLimiter()
}

func (d signerAdminAppDeps) Logf(format string, args ...interface{}) {
	logInfof(format, args...)
}
