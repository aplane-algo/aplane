// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/authz"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/rotationinventory"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	signeradmin "github.com/aplane-algo/aplane/internal/signerapp/admin"
	"github.com/aplane-algo/aplane/internal/signerapp/backupadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/storeadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/templateadmin"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

type signerAdminServices struct {
	signer *Signer
}

type signerBackupServices struct {
	backupadmin.Service
	daemon signerAdminServices
}

type signerTemplateServices struct {
	templateadmin.Service
	signer *Signer
}

var errIdentityStoreBusy = errors.New("identity store mutation is in progress")

type signerAdminAppDeps struct {
	signer *Signer
}

var (
	_ adminserver.SettingsServices = signeradmin.Service{}
	_ adminserver.KeyServices      = keyadmin.IPCService{}
	_ adminserver.BackupServices   = signerBackupServices{}
	_ adminserver.TemplateServices = signerTemplateServices{}
)

func (fs *Signer) adminServices() signerAdminServices {
	return signerAdminServices{signer: fs}
}

func (fs *Signer) adminSessionDeps() adminserver.SessionDeps {
	if fs == nil {
		return adminserver.SessionDeps{}
	}
	svc := fs.adminServices()
	return adminserver.SessionDeps{
		Identity:    svc,
		Settings:    svc.adminApp(),
		Keys:        svc.keyApp(),
		Backups:     svc.backupServices(),
		Templates:   svc.templateServices(),
		Inspection:  svc,
		Authorizer:  fs.authorizer,
		Audit:       svc,
		NodeFailure: fs.nodeFailure,
	}
}

func (s signerAdminServices) ProductIdentityRuntime() *identity.Runtime {
	if s.signer.nodeFailure() != nil {
		return nil
	}
	return s.signer.productIdentityRuntime()
}

func (s signerAdminServices) VerifyPassphrase(ir *identity.Runtime, passphrase []byte) error {
	return crypto.VerifyPassphraseWithKeyring(passphrase, ir.KeyPaths().KeystoreMetadataDir())
}

func (s signerAdminServices) UnlockIdentity(ir *identity.Runtime, passphrase []byte) (bool, int, string, string) {
	// Generation-based stores reconcile before unlock: CURRENT is the sole
	// commit record, staging residue and uncommitted attempts are discarded
	// (never resumed), and the selected generation must validate. Any
	// failure enters recovery mode with nothing deleted.
	//
	// Reconcile runs before the passphrase is verified. That ordering is
	// deliberate and safe: reconcile only removes state that is provably
	// uncommitted (no seal, not named by CURRENT) — state no caller,
	// authenticated or not, could resume — and it is exactly what startup
	// does unauthenticated. Keep it free of anything auth-gated.
	if reconcileErr := s.reconcileGenerations(ir); reconcileErr != nil {
		success, errMsg := ir.TryRecoveryUnlock(passphrase)
		if !success {
			return false, 0, errMsg, unlockFailureCode(errMsg)
		}
		logWarnf("identity is recovery-blocked: %v", reconcileErr)
		return true, 0, "", protocol.ResultCodeRecoveryBlocked
	}
	if rotationErr := s.completePendingRotation(ir, passphrase); rotationErr != nil {
		success, errMsg := ir.TryRecoveryUnlock(passphrase)
		if !success {
			return false, 0, errMsg, unlockFailureCode(errMsg)
		}
		logWarnf("identity is recovery-blocked by incomplete key rotation: %v", rotationErr)
		return true, 0, "", protocol.ResultCodeRecoveryBlocked
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
		return true, 0, "", protocol.ResultCodeRecoveryBlocked
	}
	return success, keyCount, errMsg, unlockFailureCode(errMsg)
}

// completePendingRotation resumes a root-pinned rotation before ordinary
// reload can publish signing authority. It also removes a snapshot left behind
// by a crash after the root was durably closed.
func (s signerAdminServices) completePendingRotation(
	ir *identity.Runtime,
	passphrase []byte,
) error {
	complete := func() error {
		kr, err := crypto.OpenKeyringStore(
			ir.KeyPaths().KeystoreMetadataDir(),
			passphrase,
		)
		if err != nil {
			return err
		}
		defer kr.Zero()
		report, err := rotationinventory.CompleteRotation(
			ir.KeyPaths(),
			ir.ID(),
			kr,
			passphrase,
		)
		if errors.Is(err, rotationinventory.ErrNoRotationPending) {
			return nil
		}
		if err != nil {
			return err
		}
		if report != nil && report.Resume != nil {
			logInfof(
				"completed pending key rotation for identity %s (%d rewrapped, %d re-signed)",
				ir.ID(),
				report.Resume.Rewrapped,
				report.Resume.Resigned,
			)
		}
		if report != nil && report.PreRootSnapshotDiscarded {
			logInfof(
				"discarded unreferenced pre-root rotation snapshot for identity %s",
				ir.ID(),
			)
		}
		return nil
	}
	if s.signer == nil {
		return complete()
	}
	return s.signer.withIdentityMutation(ir.ID(), complete)
}

// reconcileGenerations enforces CURRENT as the sole commit record at unlock
// (docs/ARCH_GENERATIONS.md §7) under the identity mutation lock, and
// validates the selected generation fail-closed.
func (s signerAdminServices) reconcileGenerations(ir *identity.Runtime) error {
	if s.signer == nil {
		return s.reconcileGenerationsLocked(ir)
	}
	return s.signer.withIdentityMutation(ir.ID(), func() error {
		return s.reconcileGenerationsLocked(ir)
	})
}

// reconcileGenerationsLocked performs reconciliation without acquiring the
// identity mutation lock. Callers either use reconcileGenerations or hold the
// lock across a larger validate/reload/state-transition sequence.
func (s signerAdminServices) reconcileGenerationsLocked(ir *identity.Runtime) error {
	report, err := genstore.Reconcile(ir.KeyPaths(), nil)
	if err != nil {
		return err
	}
	for _, discarded := range report.DiscardedAttempts {
		logInfof("discarded uncommitted generation %s (never committed; restore again if needed)", discarded)
	}
	for _, staging := range report.DiscardedStaging {
		logInfof("discarded generation staging residue %s", staging)
	}
	gen, err := genstore.Resolve(ir.KeyPaths())
	if err != nil {
		return err
	}
	return genstore.ValidateCurrent(gen)
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

func (s signerAdminServices) RevokeProductToken(ir *identity.Runtime) error {
	return s.signer.RevokeProductToken(ir)
}

func (s signerBackupServices) RestoreBackup(ir *identity.Runtime, req adminproto.RestoreBackupRequest) adminproto.RestoreBackupResult {
	wasRecovery := ir.IsRecovery()
	result := s.Service.RestoreBackup(ir, req)
	if result.Success && wasRecovery {
		if report, ok := s.daemon.exitRecoveryIfReconciled(ir); ok && report != nil {
			result.KeyCount = report.KeyCount
		}
	}
	s.daemon.rearmWatcherAfterGenerationFlip(ir)
	return result
}

func (s signerBackupServices) RollbackRestore(ir *identity.Runtime, req adminproto.RollbackRestoreRequest) adminproto.RollbackRestoreResult {
	wasRecovery := ir.IsRecovery()
	result := s.Service.RollbackRestore(ir, req)
	if result.Success && wasRecovery {
		s.daemon.exitRecoveryIfReconciled(ir)
	}
	s.daemon.rearmWatcherAfterGenerationFlip(ir)
	return result
}

func (s signerBackupServices) ReconcileStore(ir *identity.Runtime) adminproto.ReconcileStoreResult {
	result := adminproto.ReconcileStoreResult{}
	// Re-arm on every exit. A recovery session may have inherited a watcher
	// bound before an uncertain CURRENT flip, including when this attempt
	// fails before promotion.
	defer s.daemon.rearmWatcherAfterGenerationFlip(ir)
	report, err := s.daemon.reconcileReloadAndPromote(ir)
	if err != nil {
		ir.SetRecovery()
		result.Code = protocol.ResultCodeRecoveryBlocked
		result.Error = err.Error()
		result.State = ir.GetState().String()
		return result
	}
	if current, err := genstore.ReadCurrent(ir.KeyPaths()); err == nil {
		result.GenerationID = current
	}
	if report != nil {
		result.KeyCount = report.KeyCount
	}
	result.State = ir.GetState().String()
	result.Success = true
	return result
}

// reconcileReloadAndPromote keeps strict validation, key publication, and the
// recovery-to-unlocked transition under one identity mutation lock. This
// prevents a concurrent admin mutation from landing between validation and
// the runtime snapshot that authorizes signing.
func (s signerAdminServices) reconcileReloadAndPromote(ir *identity.Runtime) (*signertemplates.ReloadReport, error) {
	var report *signertemplates.ReloadReport
	work := func() error {
		if err := s.reconcileGenerationsLocked(ir); err != nil {
			return err
		}
		var err error
		report, err = ir.Reload()
		if err != nil {
			return fmt.Errorf("current generation failed credential reload: %w", err)
		}
		if ir.IsRecovery() && !ir.PromoteRecoveryToUnlocked() {
			return fmt.Errorf("identity state changed while store reconciliation completed")
		}
		return nil
	}
	if s.signer == nil {
		err := work()
		return report, err
	}
	err := s.signer.withIdentityMutation(ir.ID(), work)
	return report, err
}

// rearmWatcherAfterGenerationFlip rebinds the key watcher to the new current
// generation's directories after a pointer flip: fsnotify watches bind to
// inodes, so the watches armed before the flip still point at the prior
// generation.
func (s signerAdminServices) rearmWatcherAfterGenerationFlip(ir *identity.Runtime) {
	ir.StopKeyWatcher()
	ir.EnsureKeyWatcher(startKeyWatcherForDir)
}

// exitRecoveryIfReconciled promotes recovery only after the generation store
// reconciles and validates cleanly.
func (s signerAdminServices) exitRecoveryIfReconciled(ir *identity.Runtime) (*signertemplates.ReloadReport, bool) {
	// The rescan re-runs generational reconciliation and fail-closed
	// validation of the selected generation; recovery only lifts when the
	// committed state proves clean.
	report, err := s.reconcileReloadAndPromote(ir)
	if err != nil {
		logInfof("staying in recovery mode: %s failed reconciliation rescan: %v", ir.ID(), err)
		return nil, false
	}
	ir.EnsureKeyWatcher(startKeyWatcherForDir)
	if s.signer != nil {
		if hub := s.signer.adminHub(); hub != nil {
			hub.NotifyStatus(ir.GetState().String(), ir.KeyCount())
		}
	}
	return report, true
}

func (s signerTemplateServices) ListKeyTypes(ir *identity.Runtime) adminproto.ListKeyTypesResult {
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

func (s signerAdminServices) ListSentryReferences(ir *identity.Runtime) adminproto.ListSentryReferencesResult {
	var records []sentryrefs.Record
	err := s.withIdentityStoreInspection(ir.ID(), func() error {
		var err error
		records, err = sentryrefs.List(ir.KeyPaths())
		return err
	})
	if err != nil {
		code, message := identityStoreInspectionError(err, "list_failed")
		return adminproto.ListSentryReferencesResult{Code: code, Error: message}
	}
	result := adminproto.ListSentryReferencesResult{References: make([]adminproto.SentryReferenceInfo, len(records))}
	for i := range records {
		result.References[i] = adminSentryReference(records[i])
	}
	return result
}

func (s signerAdminServices) GetSentryReference(ir *identity.Runtime, req adminproto.GetSentryReferenceRequest) adminproto.GetSentryReferenceResult {
	var record sentryrefs.Record
	var found bool
	err := s.withIdentityStoreInspection(ir.ID(), func() error {
		var err error
		record, found, err = sentryrefs.Get(ir.KeyPaths(), req.Name)
		return err
	})
	if err != nil {
		code, message := identityStoreInspectionError(err, "read_failed")
		return adminproto.GetSentryReferenceResult{Code: code, Error: message}
	}
	if !found {
		return adminproto.GetSentryReferenceResult{Code: "not_found", Error: fmt.Sprintf("sentry reference %q not found", req.Name)}
	}
	return adminproto.GetSentryReferenceResult{Success: true, Reference: adminSentryReference(record)}
}

func (s signerAdminServices) ImportSentryReference(ir *identity.Runtime, req adminproto.ImportSentryReferenceRequest) adminproto.ImportSentryReferenceResult {
	var record *sentryrefs.Record
	err := s.withIdentityStoreMutation(ir.ID(), func() error {
		var err error
		record, err = sentryrefs.Import(ir.KeyPaths(), req.Name, []byte(req.EnvelopeJSON))
		return err
	})
	if err != nil {
		return adminproto.ImportSentryReferenceResult{Code: "import_failed", Error: err.Error()}
	}
	return adminproto.ImportSentryReferenceResult{Success: true, Reference: adminSentryReference(*record)}
}

func (s signerAdminServices) RemoveSentryReference(ir *identity.Runtime, req adminproto.RemoveSentryReferenceRequest) adminproto.RemoveSentryReferenceResult {
	var removed bool
	var componentKey string
	err := s.withIdentityStoreMutation(ir.ID(), func() error {
		existing, found, err := sentryrefs.Get(ir.KeyPaths(), req.Name)
		if err != nil {
			return err
		}
		if found {
			componentKey = existing.ComponentKey
		}
		removed, err = sentryrefs.Delete(ir.KeyPaths(), req.Name)
		return err
	})
	if err != nil {
		return adminproto.RemoveSentryReferenceResult{Name: req.Name, Code: "remove_failed", Error: err.Error()}
	}
	return adminproto.RemoveSentryReferenceResult{
		Success: true, Name: req.Name, ComponentKey: componentKey, Removed: removed,
	}
}

func (s signerAdminServices) ExportSentryPublic(ir *identity.Runtime, req adminproto.ExportSentryPublicRequest) adminproto.ExportSentryPublicResult {
	componentKey, err := witness.NormalizeID(req.WitnessKeyID)
	if err != nil {
		return adminproto.ExportSentryPublicResult{Code: "invalid_witness_key_id", Error: err.Error()}
	}
	var envelope witness.PublicReference
	var found bool
	err = s.withIdentityStoreInspection(ir.ID(), func() error {
		var err error
		envelope, found, err = apkeys.ReadWitnessPublicMetadata(ir.KeyPaths(), componentKey)
		return err
	})
	if err != nil {
		code, message := identityStoreInspectionError(err, "export_failed")
		return adminproto.ExportSentryPublicResult{Code: code, Error: message}
	}
	if !found {
		return adminproto.ExportSentryPublicResult{Code: "not_found", Error: fmt.Sprintf("sentry public metadata for %s not found", componentKey)}
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return adminproto.ExportSentryPublicResult{Code: "encode_failed", Error: err.Error()}
	}
	data = append(data, '\n')
	return adminproto.ExportSentryPublicResult{Success: true, WitnessKeyID: componentKey, EnvelopeJSON: string(data)}
}

func (s signerAdminServices) ListGenerations(ir *identity.Runtime) adminproto.GenerationInventory {
	var report genstore.ReconcileReport
	err := s.withIdentityStoreInspection(ir.ID(), func() error {
		generational, err := genstore.IsGenerational(ir.KeyPaths())
		if err != nil {
			return err
		}
		if !generational {
			return fmt.Errorf("store does not use generation-based storage")
		}
		report, err = genstore.Inspect(ir.KeyPaths(), nil)
		return err
	})
	if err != nil {
		code, message := identityStoreInspectionError(err, "inspect_failed")
		return adminproto.GenerationInventory{Code: code, Error: message}
	}
	return adminproto.GenerationInventory{
		Current: report.Current, SealedPriors: report.SealedPriors,
		PendingAttempts: report.DiscardedAttempts, PendingStaging: report.DiscardedStaging,
		RetainedUnsealedParent: report.RetainedUnsealedParent,
	}
}

func (s signerAdminServices) withIdentityStoreMutation(identityID string, fn func() error) error {
	if s.signer == nil {
		return fn()
	}
	return s.signer.withIdentityMutation(identityID, fn)
}

func (s signerAdminServices) withIdentityStoreInspection(identityID string, fn func() error) error {
	if s.signer == nil {
		return fn()
	}
	return s.signer.tryWithIdentityInspection(identityID, fn)
}

func identityStoreInspectionError(err error, fallbackCode string) (string, string) {
	if errors.Is(err, errIdentityStoreBusy) {
		return protocol.ResultCodeIdentityBusy, err.Error()
	}
	return fallbackCode, err.Error()
}

func adminSentryReference(record sentryrefs.Record) adminproto.SentryReferenceInfo {
	return adminproto.SentryReferenceInfo{
		Schema: record.Schema, Name: record.Name, ComponentKey: record.ComponentKey, KeyType: record.KeyType,
		PublicKeyEncoding: record.PublicKeyEncoding, PublicKeyHex: record.PublicKeyHex,
		PublicKeySize: record.PublicKeySize, PublicKeySHA256: record.PublicKeySHA256,
		ImportedAt: record.ImportedAt, MigrationOrigin: record.MigrationOrigin,
	}
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

func (s signerAdminServices) backupServices() signerBackupServices {
	return signerBackupServices{Service: s.backupApp(), daemon: s}
}

func (s signerAdminServices) templateApp() templateadmin.Service {
	return templateadmin.Service{Deps: signerAdminAppDeps(s)}
}

func (s signerAdminServices) templateServices() signerTemplateServices {
	return signerTemplateServices{Service: s.templateApp(), signer: s.signer}
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
