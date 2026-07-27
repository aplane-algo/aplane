// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/authz"
	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/protocol"
	signeradmin "github.com/aplane-algo/aplane/internal/signerapp/admin"
	"github.com/aplane-algo/aplane/internal/signerapp/backupadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/storeadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/templateadmin"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
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
	// Generation-based stores reconcile before unlock: CURRENT is the sole
	// commit record, staging residue and uncommitted attempts are discarded
	// (never resumed), and the selected generation must validate. Any
	// failure enters recovery mode with nothing deleted.
	if generational, genErr := genstore.IsGenerational(ir.KeyPaths(), ir.ID()); genErr != nil {
		errMsg := fmt.Sprintf("failed to inspect store layout: %v", genErr)
		return false, 0, errMsg, protocol.ErrCodeUnlockFailed
	} else if generational {
		if reconcileErr := s.reconcileGenerations(ir); reconcileErr != nil {
			success, errMsg := ir.TryRecoveryUnlock(passphrase)
			if !success {
				return false, 0, errMsg, unlockFailureCode(errMsg)
			}
			logWarnf("identity is recovery-blocked: %v", reconcileErr)
			return true, 0, "", protocol.ResultCodeActivationIncomplete
		}
	}
	incomplete, err := recovered.IncompleteActivationIDs(ir.KeyPaths(), ir.ID())
	if err != nil {
		errMsg := fmt.Sprintf("failed to inspect activation recovery state: %v", err)
		return false, 0, errMsg, protocol.ErrCodeUnlockFailed
	}
	if len(incomplete) > 0 {
		success, errMsg := ir.TryRecoveryUnlock(passphrase)
		if !success {
			return false, 0, errMsg, unlockFailureCode(errMsg)
		}
		if keyCount, ok := s.reconcileIncompleteActivationsAtUnlock(ir, incomplete); ok {
			return true, keyCount, "", ""
		}
		return true, 0, "", protocol.ResultCodeActivationIncomplete
	}
	success, keyCount, errMsg := ir.TryUnlock(passphrase, func() {
		ir.EnsureKeyWatcher(startKeyWatcherForDir)
	})
	if !success && signertemplates.IsGenerationValidationError(errMsg) {
		// Content defects in the selected generation are a recovery
		// condition, not an unlock failure: the passphrase was right and
		// the operator resolves the store from recovery mode.
		recoverySuccess, recoveryErrMsg := ir.TryRecoveryUnlock(passphrase)
		if !recoverySuccess {
			return false, 0, recoveryErrMsg, unlockFailureCode(recoveryErrMsg)
		}
		logWarnf("identity is recovery-blocked: %s", errMsg)
		return true, 0, "", protocol.ResultCodeActivationIncomplete
	}
	return success, keyCount, errMsg, unlockFailureCode(errMsg)
}

// reconcileGenerations enforces CURRENT as the sole commit record at unlock
// (docs/ARCH_GENERATIONS.md §7) under the identity mutation lock, and
// validates the selected generation fail-closed.
func (s signerAdminServices) reconcileGenerations(ir *identity.Runtime) error {
	reconcile := func() error {
		report, err := genstore.Reconcile(ir.KeyPaths(), ir.ID(), nil)
		if err != nil {
			return err
		}
		for _, discarded := range report.DiscardedAttempts {
			logInfof("discarded uncommitted generation %s (never resumed; review and activate again)", discarded)
		}
		for _, staging := range report.DiscardedStaging {
			logInfof("discarded generation staging residue %s", staging)
		}
		gen, err := genstore.Resolve(ir.KeyPaths(), ir.ID())
		if err != nil {
			return err
		}
		return genstore.ValidateCurrent(gen)
	}
	if s.signer == nil {
		return reconcile()
	}
	return s.signer.withIdentityMutation(ir.ID(), reconcile)
}

// reconcileIncompleteActivationsAtUnlock runs automatic reconciliation after
// a recovery unlock has made the master key available: a single completed
// activation has its cleanup finished, a single interrupted activation is
// rolled back to the exact pre-activation state. Multiple markers cannot be
// ordered safely, so they fail closed into recovery for explicit operator
// resolution. Reports the reloaded key count and whether the identity left
// recovery mode; any failure keeps the identity in recovery. [P1, P1b]
func (s signerAdminServices) reconcileIncompleteActivationsAtUnlock(ir *identity.Runtime, incomplete []string) (int, bool) {
	if len(incomplete) != 1 {
		logInfof("staying in recovery mode: %d incomplete activations for %s need explicit resolution: %v",
			len(incomplete), ir.ID(), incomplete)
		return 0, false
	}
	restoreID := incomplete[0]

	// Validate and decrypt the journal and snapshot before anything touches
	// the active store; reconciliation direction comes from the journal.
	var state recovered.ActivationState
	if err := ir.WithMasterKey(func(masterKey []byte) error {
		journal, snapshot, err := recovered.LoadActivation(ir.KeyPaths(), ir.ID(), restoreID, masterKey)
		if err != nil {
			return err
		}
		snapshot.Zero()
		state = journal.State
		return nil
	}); err != nil {
		logInfof("staying in recovery mode: cannot load activation state %s for %s: %v", restoreID, ir.ID(), err)
		return 0, false
	}

	if state == recovered.ActivationCompleted {
		// The activation succeeded before the interruption; finish its
		// cleanup instead of rolling it back.
		result := s.ActivateRecovered(ir, adminproto.ActivateRecoveredRequest{RestoreID: restoreID})
		if !result.Success {
			logInfof("staying in recovery mode: cleanup of completed activation %s failed: %s", restoreID, result.Error)
			return 0, false
		}
		logInfof("finished cleanup of completed activation %s during unlock", restoreID)
		s.auditAutoReconcile(ir, adminproto.RollbackRecoveredResult{}, result)
		return result.KeyCount, ir.IsUnlocked()
	}

	result := s.RollbackRecovered(ir, adminproto.RollbackRecoveredRequest{RestoreID: restoreID})
	if !result.Success {
		logInfof("staying in recovery mode: automatic rollback of activation %s failed: %s", restoreID, result.Error)
		return 0, false
	}
	logInfof("rolled back interrupted activation %s during unlock; the recovered batch remains available for review", restoreID)
	s.auditAutoReconcile(ir, result, adminproto.ActivateRecoveredResult{})
	return result.KeyCount, ir.IsUnlocked()
}

// auditAutoReconcile records the automatic unlock-time reconciliation with
// the same events the explicit admin operations emit.
func (s signerAdminServices) auditAutoReconcile(
	ir *identity.Runtime,
	rolledBack adminproto.RollbackRecoveredResult,
	activated adminproto.ActivateRecoveredResult,
) {
	if s.signer == nil || s.signer.auditLog == nil {
		return
	}
	ctx := adminserver.SessionContext{TargetIdentityID: ir.ID(), Transport: "unlock"}
	switch {
	case rolledBack.Success:
		s.signer.auditLog.LogBackupActivationRolledBackContext(ctx, rolledBack)
	case activated.Success:
		s.signer.auditLog.LogBackupActivatedContext(ctx, activated)
	}
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

func (s signerAdminServices) BuildPolicySnapshot(ir *identity.Runtime, target adminproto.PolicyTarget) adminproto.PolicySnapshot {
	return s.adminApp().BuildPolicySnapshot(ir, target)
}

func (s signerAdminServices) ReplacePolicy(ir *identity.Runtime, req adminproto.ReplacePolicyRequest) adminproto.PolicySnapshot {
	return s.adminApp().ReplacePolicy(ir, req)
}

func (s signerAdminServices) ValidatePolicy(ir *identity.Runtime, req adminproto.ValidatePolicyRequest) adminproto.ValidatePolicyResult {
	return s.adminApp().ValidatePolicy(ir, req)
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

func (s signerAdminServices) RecoverBackup(ir *identity.Runtime, req adminproto.RecoverBackupRequest) adminproto.RecoverBackupResult {
	return s.backupApp().RecoverBackup(ir, req)
}

func (s signerAdminServices) ListRecovered(ir *identity.Runtime) adminproto.ListRecoveredResult {
	return s.backupApp().ListRecovered(ir)
}

func (s signerAdminServices) ReviewRecovered(ir *identity.Runtime, restoreID string) adminproto.ReviewRecoveredResult {
	return s.backupApp().ReviewRecovered(ir, restoreID)
}

func (s signerAdminServices) ActivateRecovered(ir *identity.Runtime, req adminproto.ActivateRecoveredRequest) adminproto.ActivateRecoveredResult {
	wasRecovery := ir.IsRecovery()
	result := s.backupApp().ActivateRecovered(ir, req)
	if result.Success && wasRecovery {
		s.exitRecoveryIfReconciled(ir)
	}
	if result.Success {
		s.rearmWatcherAfterGenerationFlip(ir)
	}
	return result
}

func (s signerAdminServices) RollbackRecovered(ir *identity.Runtime, req adminproto.RollbackRecoveredRequest) adminproto.RollbackRecoveredResult {
	wasRecovery := ir.IsRecovery()
	result := s.backupApp().RollbackRecovered(ir, req)
	if result.Success && wasRecovery {
		s.exitRecoveryIfReconciled(ir)
	}
	if result.Success {
		s.rearmWatcherAfterGenerationFlip(ir)
	}
	return result
}

// rearmWatcherAfterGenerationFlip rebinds the key watcher to the new current
// generation's directories after a pointer flip: fsnotify watches bind to
// inodes, so the watches armed before the flip still point at the prior
// generation.
func (s signerAdminServices) rearmWatcherAfterGenerationFlip(ir *identity.Runtime) {
	generational, err := genstore.IsGenerational(ir.KeyPaths(), ir.ID())
	if err != nil || !generational {
		return
	}
	ir.StopKeyWatcher()
	ir.EnsureKeyWatcher(startKeyWatcherForDir)
}

// exitRecoveryIfReconciled promotes recovery to unlocked only after a rescan
// of every recovered batch confirms no incomplete activation marker remains.
// Resolving one batch must never re-enable signing while another batch is
// still unreconciled: the rescan, not the operation that just succeeded, is
// authoritative. Reports whether the identity was unlocked. [P1]
func (s signerAdminServices) exitRecoveryIfReconciled(ir *identity.Runtime) bool {
	incomplete, err := recovered.IncompleteActivationIDs(ir.KeyPaths(), ir.ID())
	if err != nil {
		logInfof("staying in recovery mode: failed to rescan activation state for %s: %v", ir.ID(), err)
		return false
	}
	if len(incomplete) > 0 {
		logInfof("staying in recovery mode: %d incomplete activation(s) remain for %s", len(incomplete), ir.ID())
		return false
	}
	ir.SetUnlocked()
	ir.EnsureKeyWatcher(startKeyWatcherForDir)
	if s.signer != nil {
		if hub := s.signer.adminHub(); hub != nil {
			hub.NotifyStatus(ir.ID(), ir.GetState().String(), ir.KeyCount())
		}
	}
	return true
}

func (s signerAdminServices) PurgeRecovered(ir *identity.Runtime, req adminproto.PurgeRecoveredRequest) adminproto.PurgeRecoveredResult {
	return s.backupApp().PurgeRecovered(ir, req)
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

func (d signerAdminAppDeps) GenesisHashMappings() map[string]string {
	cfg := d.signer.ConfigSnapshot()
	return maps.Clone(cfg.GenesisHashNetworks)
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
