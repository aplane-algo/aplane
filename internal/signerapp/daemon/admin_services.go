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
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	signeradmin "github.com/aplane-algo/aplane/internal/signerapp/admin"
	"github.com/aplane-algo/aplane/internal/signerapp/backupadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/storeadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/templateadmin"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

type signerAdminServices struct {
	signer  *Signer
	product *productruntime.Runtime
}

type signerBackupServices struct {
	backupadmin.Service
	daemon signerAdminServices
}

type signerTemplateServices struct {
	templateadmin.Service
	signer *Signer
}

var errStoreBusy = errors.New("product store mutation is in progress")

type signerAdminAppDeps struct {
	signer *Signer
}

var (
	_ adminserver.ProductServices         = signerAdminServices{}
	_ adminserver.SettingsServices        = signeradmin.Service{}
	_ adminserver.KeyServices             = keyadmin.IPCService{}
	_ adminserver.BackupServices          = signerBackupServices{}
	_ adminserver.TemplateServices        = signerTemplateServices{}
	_ adminserver.StoreInspectionServices = signerAdminServices{}
)

func (fs *Signer) adminServices() signerAdminServices {
	return signerAdminServices{signer: fs, product: fs.productRuntime()}
}

func (fs *Signer) adminSessionDeps() adminserver.SessionDeps {
	if fs == nil {
		return adminserver.SessionDeps{}
	}
	svc := fs.adminServices()
	return adminserver.SessionDeps{
		Product:     svc,
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

func (s signerAdminServices) ProductRuntime() *productruntime.Runtime {
	return s.product
}

func (s signerAdminServices) VerifyPassphrase(passphrase []byte) error {
	return crypto.VerifyPassphraseWithStoreRoot(passphrase, s.ProductRuntime().KeyPaths().KeystoreMetadataDir())
}

func (s signerAdminServices) UnlockIdentity(passphrase []byte) (bool, int, string, string) {
	ir := s.ProductRuntime()
	// Reconciliation authenticates the sole store root before it relocates or
	// deletes residue. A valid root with damaged selected content still opens
	// the keyring and enters recovery; no generation is selected heuristically.
	if reconcileErr := s.reconcileGenerations(ir, passphrase); reconcileErr != nil {
		success, errMsg := ir.TryRecoveryUnlock(passphrase)
		if !success {
			return false, 0, errMsg, unlockFailureCode(errMsg)
		}
		logWarnf("identity is recovery-blocked: %v", reconcileErr)
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

// reconcileGenerations opens the authenticated root under the store mutation
// lock and validates the selected generation fail-closed.
func (s signerAdminServices) reconcileGenerations(ir *productruntime.Runtime, passphrase []byte) error {
	work := func() error {
		_, kr, err := genstore.OpenStoreRootSelection(ir.KeyPaths(), passphrase)
		if err != nil {
			return err
		}
		defer kr.Zero()
		return s.reconcileGenerationsLocked(ir, kr)
	}
	if s.signer == nil {
		return work()
	}
	return s.signer.withStoreMutation(work)
}

// reconcileGenerationsLocked performs reconciliation without acquiring the
// store mutation lock. Callers either use reconcileGenerations or hold the
// lock across a larger validate/reload/state-transition sequence.
func (s signerAdminServices) reconcileGenerationsLocked(ir *productruntime.Runtime, kr *crypto.Keyring) error {
	preview, err := genstore.InspectStoreRoot(ir.KeyPaths(), kr, nil)
	if err != nil {
		return err
	}
	if len(preview.Quarantined) > 0 {
		if s.signer == nil || s.signer.auditLog == nil {
			return fmt.Errorf("reconcile: durable audit unavailable; refusing generation quarantine")
		}
		for _, candidate := range preview.Quarantined {
			if err := s.signer.auditLog.LogGenerationQuarantineIntentDurable(candidate); err != nil {
				return fmt.Errorf(
					"reconcile: record durable quarantine intent for %s: %w",
					candidate.GenerationID,
					err,
				)
			}
		}
	}
	report, err := genstore.ReconcileStoreRoot(ir.KeyPaths(), kr, nil)
	if s.signer != nil && s.signer.auditLog != nil {
		for _, quarantined := range report.Quarantined {
			s.signer.auditLog.LogGenerationQuarantined(quarantined)
		}
	}
	if err != nil {
		return err
	}
	for _, quarantined := range report.Quarantined {
		logInfof(
			"quarantined non-authoritative generation %s (at_mint_match=%t bytes=%d)",
			quarantined.GenerationID,
			quarantined.AtMintInventoryMatch,
			quarantined.EncodedBytes,
		)
	}
	for _, staging := range report.DiscardedStaging {
		logInfof("discarded generation staging residue %s", staging)
	}
	_, err = genstore.ResolveStoreRootWithKeyring(ir.KeyPaths(), kr)
	return err
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
	return s.storeApp().InitializeStore(req)
}

func (s signerAdminServices) ChangeStorePassphrase(req adminproto.ChangeStorePassphraseRequest) adminproto.ChangeStorePassphraseResult {
	return s.storeApp().ChangeStorePassphrase(req)
}

func (s signerAdminServices) NewSessionIdentity(method string) *auth.Identity {
	return auth.NewProductIdentity(method)
}

func (s signerAdminServices) LogAuthorizationDenied(ctx adminserver.SessionContext, action auth.Action, resource auth.Resource, reason string) {
	if s.signer == nil || s.signer.auditLog == nil {
		return
	}
	s.signer.auditLog.LogAuthorizationDenied(ctx, action, resource, reason)
}

func (s signerAdminServices) RevokeProductToken() error {
	return s.signer.RevokeProductToken(s.ProductRuntime())
}

func (s signerBackupServices) RestoreBackup(req adminproto.RestoreBackupRequest) adminproto.RestoreBackupResult {
	ir := s.Runtime
	wasRecovery := ir.IsRecovery()
	result := s.Service.RestoreBackup(req)
	if result.Success && wasRecovery {
		if report, ok := s.daemon.exitRecoveryIfReconciled(ir); ok && report != nil {
			result.KeyCount = report.KeyCount
		}
	}
	s.daemon.rearmWatcherAfterGenerationFlip(ir)
	return result
}

func (s signerBackupServices) RollbackRestore(req adminproto.RollbackRestoreRequest) adminproto.RollbackRestoreResult {
	ir := s.Runtime
	wasRecovery := ir.IsRecovery()
	result := s.Service.RollbackRestore(req)
	if result.Success && wasRecovery {
		s.daemon.exitRecoveryIfReconciled(ir)
	}
	s.daemon.rearmWatcherAfterGenerationFlip(ir)
	return result
}

func (s signerBackupServices) ReconcileStore() adminproto.ReconcileStoreResult {
	ir := s.Runtime
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
	if active, err := ir.ActivePaths(); err == nil {
		result.GenerationID = active.GenerationID()
	}
	if report != nil {
		result.KeyCount = report.KeyCount
	}
	result.State = ir.GetState().String()
	result.Success = true
	return result
}

// reconcileReloadAndPromote keeps strict validation, key publication, and the
// recovery-to-unlocked transition under one store mutation lock. This
// prevents a concurrent admin mutation from landing between validation and
// the runtime snapshot that authorizes signing.
func (s signerAdminServices) reconcileReloadAndPromote(ir *productruntime.Runtime) (*signertemplates.ReloadReport, error) {
	var report *signertemplates.ReloadReport
	work := func() error {
		if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
			return s.reconcileGenerationsLocked(ir, kr)
		}); err != nil {
			return err
		}
		var err error
		report, err = ir.Reload()
		if err != nil {
			return fmt.Errorf("current generation failed credential reload: %w", err)
		}
		if ir.IsRecovery() && !ir.PromoteRecoveryToUnlocked() {
			return fmt.Errorf("runtime state changed while store reconciliation completed")
		}
		return nil
	}
	if s.signer == nil {
		err := work()
		return report, err
	}
	err := s.signer.withStoreMutation(work)
	return report, err
}

// rearmWatcherAfterGenerationFlip rebinds the key watcher to the new current
// generation's directories after a pointer flip: fsnotify watches bind to
// inodes, so the watches armed before the flip still point at the prior
// generation.
func (s signerAdminServices) rearmWatcherAfterGenerationFlip(ir *productruntime.Runtime) {
	ir.StopKeyWatcher()
	ir.EnsureKeyWatcher(startKeyWatcherForDir)
}

// exitRecoveryIfReconciled promotes recovery only after the generation store
// reconciles and validates cleanly.
func (s signerAdminServices) exitRecoveryIfReconciled(ir *productruntime.Runtime) (*signertemplates.ReloadReport, bool) {
	// The rescan re-runs generational reconciliation and fail-closed
	// validation of the selected generation; recovery only lifts when the
	// committed state proves clean.
	report, err := s.reconcileReloadAndPromote(ir)
	if err != nil {
		logInfof("staying in recovery mode: signer store failed reconciliation rescan: %v", err)
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

func (s signerTemplateServices) ListKeyTypes() adminproto.ListKeyTypesResult {
	ir := s.Runtime
	resp, err := s.signer.restService().KeyTypes(ir)
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

func (s signerAdminServices) ListSentryReferences() adminproto.ListSentryReferencesResult {
	ir := s.ProductRuntime()
	var records []sentryrefs.Record
	err := s.withStoreInspection(func() error {
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

func (s signerAdminServices) GetSentryReference(req adminproto.GetSentryReferenceRequest) adminproto.GetSentryReferenceResult {
	ir := s.ProductRuntime()
	var record sentryrefs.Record
	var found bool
	err := s.withStoreInspection(func() error {
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

func (s signerAdminServices) ImportSentryReference(req adminproto.ImportSentryReferenceRequest) adminproto.ImportSentryReferenceResult {
	ir := s.ProductRuntime()
	var record *sentryrefs.Record
	err := s.withStoreMutation(func() error {
		var err error
		record, err = sentryrefs.Import(ir.KeyPaths(), req.Name, []byte(req.EnvelopeJSON))
		return err
	})
	if err != nil {
		return adminproto.ImportSentryReferenceResult{Code: "import_failed", Error: err.Error()}
	}
	return adminproto.ImportSentryReferenceResult{Success: true, Reference: adminSentryReference(*record)}
}

func (s signerAdminServices) RemoveSentryReference(req adminproto.RemoveSentryReferenceRequest) adminproto.RemoveSentryReferenceResult {
	ir := s.ProductRuntime()
	var removed bool
	var componentKey string
	err := s.withStoreMutation(func() error {
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

func (s signerAdminServices) ExportSentryPublic(req adminproto.ExportSentryPublicRequest) adminproto.ExportSentryPublicResult {
	ir := s.ProductRuntime()
	componentKey, err := witness.NormalizeID(req.WitnessKeyID)
	if err != nil {
		return adminproto.ExportSentryPublicResult{Code: "invalid_witness_key_id", Error: err.Error()}
	}
	var envelope witness.PublicReference
	var found bool
	err = s.withStoreInspection(func() error {
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

func (s signerAdminServices) ListGenerations() adminproto.GenerationInventory {
	ir := s.ProductRuntime()
	var report genstore.ReconcileReport
	var quarantined []genstore.QuarantineRecord
	err := s.withStoreInspection(func() error {
		generational, err := genstore.IsGenerational(ir.KeyPaths())
		if err != nil {
			return err
		}
		if !generational {
			return fmt.Errorf("store does not use generation-based storage")
		}
		report, err = genstore.Inspect(ir.KeyPaths(), nil)
		if err != nil {
			return err
		}
		quarantined, err = genstore.ListQuarantined(ir.KeyPaths())
		return err
	})
	if err != nil {
		code, message := identityStoreInspectionError(err, "inspect_failed")
		return adminproto.GenerationInventory{Code: code, Error: message}
	}
	quarantined = append(quarantined, report.Quarantined...)
	quarantineInfo := make([]adminproto.QuarantinedGenerationInfo, 0, len(quarantined))
	for _, record := range quarantined {
		quarantineInfo = append(quarantineInfo, adminQuarantinedGeneration(record))
	}
	return adminproto.GenerationInventory{
		Current: report.Current, SealedPriors: report.SealedPriors,
		Quarantined: quarantineInfo, PendingStaging: report.DiscardedStaging,
		RetainedUnsealedParent: report.RetainedUnsealedParent,
	}
}

func (s signerAdminServices) PruneGenerationQuarantine(
	req adminproto.PruneGenerationQuarantineRequest,
) adminproto.PruneGenerationQuarantineResult {
	ir := s.ProductRuntime()
	var pruned []genstore.QuarantinePruneResult
	err := s.withStoreMutation(func() error {
		var err error
		pruned, err = genstore.PruneQuarantined(ir.KeyPaths(), req.GenerationIDs)
		return err
	})
	result := adminproto.PruneGenerationQuarantineResult{
		Pruned: make([]adminproto.PrunedQuarantinedGeneration, 0, len(pruned)),
	}
	for _, item := range pruned {
		result.Pruned = append(result.Pruned, adminproto.PrunedQuarantinedGeneration{
			GenerationID:  item.GenerationID,
			EncodedBytes:  item.EncodedBytes,
			AlreadyAbsent: item.AlreadyAbsent,
		})
	}
	if err != nil {
		result.Code = protocol.ResultCodeQuarantinePruneFailed
		result.Error = err.Error()
		return result
	}
	result.Success = true
	return result
}

func adminQuarantinedGeneration(record genstore.QuarantineRecord) adminproto.QuarantinedGenerationInfo {
	return adminproto.QuarantinedGenerationInfo{
		GenerationID:         record.GenerationID,
		ParentID:             record.ParentID,
		ManifestSHA256:       record.ManifestSHA256,
		LiveInventorySHA256:  record.LiveInventorySHA256,
		AtMintInventoryMatch: record.AtMintInventoryMatch,
		EntryCount:           record.EntryCount,
		EncodedBytes:         record.EncodedBytes,
	}
}

func (s signerAdminServices) withStoreMutation(fn func() error) error {
	if s.signer == nil {
		return fn()
	}
	return s.signer.withStoreMutation(fn)
}

func (s signerAdminServices) withStoreInspection(fn func() error) error {
	if s.signer == nil {
		return fn()
	}
	return s.signer.tryWithStoreInspection(fn)
}

func identityStoreInspectionError(err error, fallbackCode string) (string, string) {
	if errors.Is(err, errStoreBusy) {
		return protocol.ResultCodeStoreBusy, err.Error()
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
	return signeradmin.Service{Deps: signerAdminAppDeps{signer: s.signer}, Runtime: s.ProductRuntime()}
}

func (s signerAdminServices) backupApp() backupadmin.Service {
	return backupadmin.Service{Deps: signerAdminAppDeps{signer: s.signer}, Runtime: s.ProductRuntime()}
}

func (s signerAdminServices) backupServices() signerBackupServices {
	return signerBackupServices{Service: s.backupApp(), daemon: s}
}

func (s signerAdminServices) templateApp() templateadmin.Service {
	return templateadmin.Service{Deps: signerAdminAppDeps{signer: s.signer}, Runtime: s.ProductRuntime()}
}

func (s signerAdminServices) templateServices() signerTemplateServices {
	return signerTemplateServices{Service: s.templateApp(), signer: s.signer}
}

func (s signerAdminServices) storeApp() storeadmin.Service {
	return storeadmin.Service{
		Deps:           signerAdminAppDeps{signer: s.signer},
		Runtime:        s.ProductRuntime(),
		AuditLog:       s.signer.auditLog,
		UnlockIdentity: s.UnlockIdentity,
	}
}

func (s signerAdminServices) keyApp() keyadmin.IPCService {
	return keyadmin.IPCService{
		Service:             s.signer.restService().Deps.KeyAdmin,
		GenerateGenericLSig: s.signer.generateGenericLSigForRuntimeContext,
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

func (d signerAdminAppDeps) WithStoreMutation(fn func() error) error {
	return d.signer.withStoreMutation(fn)
}

func (d signerAdminAppDeps) RestoreLimiter() backupadmin.RestoreLimiter {
	return d.signer.restoreAttemptLimiter()
}

func (d signerAdminAppDeps) Logf(format string, args ...interface{}) {
	logInfof(format, args...)
}
