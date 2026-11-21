// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"

	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/protocol"
	signeradmin "github.com/aplane-algo/aplane/internal/signerapp/admin"
	"github.com/aplane-algo/aplane/internal/signerapp/backupadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
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
	return signerAdminServices{signer: fs}
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
	return s.signer.productRuntime()
}

// VerifyPassphrase checks a login passphrase against the store root. A
// failure other than a passphrase that does not open the root means the store
// root is damaged or unreadable; its cause is logged here, because the login
// reply carries none of it.
func (s signerAdminServices) VerifyPassphrase(passphrase []byte) error {
	err := crypto.VerifyPassphraseWithStoreRoot(passphrase, s.ProductRuntime().KeyPaths().ProductDir())
	if err != nil && !errors.Is(err, crypto.ErrInvalidPassphrase) {
		logErrorf("admin login: the store root could not be opened: %v", err)
	}
	return err
}

func (s signerAdminServices) UnlockIdentity(passphrase []byte) (bool, int, string, string) {
	ir := s.ProductRuntime()
	// Reconciliation authenticates the sole store root before it relocates or
	// deletes residue. A valid root with damaged selected content still opens
	// the keyring and enters recovery; no generation is selected heuristically.
	if reconcileErr := s.reconcileGenerations(ir, passphrase); reconcileErr != nil {
		success, errMsg := ir.TryRecoveryUnlock(passphrase)
		if !success {
			return failedUnlock(errMsg)
		}
		logWarnf("identity is recovery-blocked: %v", reconcileErr)
		return true, 0, "", protocol.ResultCodeRecoveryBlocked
	}
	success, keyCount, errMsg := ir.TryUnlock(passphrase, func() {
		ir.EnsureKeyWatcher(startKeyWatcherForDir)
	})
	if !success && errMsg == signerruntime.RecoveryDuringUnlockMessage {
		return answerFencedUnlock(ir, errMsg)
	}
	if !success && signertemplates.IsGenerationValidationError(errMsg) {
		// Content defects in the selected generation are a recovery
		// condition, not an unlock failure: the passphrase was right and
		// the operator resolves the store from recovery mode.
		recoverySuccess, recoveryErrMsg := ir.TryRecoveryUnlock(passphrase)
		if !recoverySuccess {
			return failedUnlock(recoveryErrMsg)
		}
		logWarnf("identity is recovery-blocked: %s", errMsg)
		return true, 0, "", protocol.ResultCodeRecoveryBlocked
	}
	if !success {
		return failedUnlock(errMsg)
	}
	return true, keyCount, "", ""
}

// answerFencedUnlock answers an unlock that met an entry into recovery and
// so published nothing, from the state the signer is in now: a reconcile on
// another connection may have lifted that recovery, or a lock come in, since.
func answerFencedUnlock(ir *productruntime.Runtime, errMsg string) (bool, int, string, string) {
	switch ir.GetState() {
	case signerruntime.SignerStateRecovery:
		// A store change on another connection ended in doubt while this
		// unlock ran; the signer stays in recovery, as that change answered.
		logWarnf("identity is recovery-blocked: %s", errMsg)
		return true, 0, "", protocol.ResultCodeRecoveryBlocked
	case signerruntime.SignerStateUnlocked:
		return true, ir.KeyCount(), "", ""
	default:
		return failedUnlock(signerruntime.LockedDuringUnlockMessage)
	}
}

// failedUnlock answers an unlock that failed with errMsg. A failure other
// than a wrong passphrase, such as a store root that cannot be opened, is
// logged with its cause; an unlock that lost a race to a lock or a store
// maintenance is expected and logged below error.
func failedUnlock(errMsg string) (bool, int, string, string) {
	code := unlockFailureCode(errMsg)
	switch {
	case code != protocol.ErrCodeUnlockFailed:
	case errMsg == signerruntime.LockedDuringUnlockMessage, errMsg == signerruntime.MaintenanceInProgressMessage:
		logInfof("unlock did not complete: %s", errMsg)
	default:
		logErrorf("unlock failed: %s", errMsg)
	}
	return false, 0, errMsg, code
}

// reconcileGenerations opens the authenticated root under the store mutation
// lock and validates the selected generation fail-closed.
func (s signerAdminServices) reconcileGenerations(ir *productruntime.Runtime, passphrase []byte) error {
	return s.withStoreMutation(func() error {
		_, kr, err := genstore.OpenStoreRootSelection(ir.KeyPaths(), passphrase)
		if err != nil {
			return err
		}
		defer kr.Zero()
		return s.reconcileGenerationsLocked(ir, kr)
	})
}

// reconcileGenerationsLocked performs reconciliation without acquiring the
// store mutation lock. Callers either use reconcileGenerations or hold the
// lock across a larger validate/reload/state-transition sequence.
func (s signerAdminServices) reconcileGenerationsLocked(ir *productruntime.Runtime, kr *crypto.Keyring) error {
	preview, err := genstore.InspectStoreRoot(ir.KeyPaths(), kr)
	if err != nil {
		return err
	}
	if len(preview.Quarantined) > 0 {
		if s.signer.auditLog == nil {
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
	report, err := genstore.ReconcileStoreRoot(ir.KeyPaths(), kr)
	if s.signer.auditLog != nil {
		for _, quarantined := range report.Quarantined {
			s.signer.auditLog.LogGenerationQuarantined(quarantined)
		}
	}
	if err != nil {
		return err
	}
	for _, quarantined := range report.Quarantined {
		logInfof(
			"quarantined non-authoritative generation %s (at_mint_match=%t bytes=%d term_verified=%d term_unavailable=%d term_failed=%d)",
			quarantined.GenerationID,
			quarantined.AtMintInventoryMatch,
			quarantined.EncodedBytes,
			quarantined.TermValidation.Verified,
			quarantined.TermValidation.TermUnavailable,
			quarantined.TermValidation.Failed,
		)
	}
	for _, staging := range report.DiscardedStaging {
		logInfof("discarded generation staging residue %s", staging)
	}
	_, err = genstore.ResolveStoreRootWithKeyring(ir.KeyPaths(), kr)
	return err
}

func unlockFailureCode(errMsg string) string {
	switch errMsg {
	case "":
		return ""
	case productruntime.InvalidPassphraseMessage:
		return protocol.ErrCodeInvalidPassphrase
	default:
		return protocol.ErrCodeUnlockFailed
	}
}

func (s signerAdminServices) InitializeStore(req adminproto.InitializeStoreRequest) adminproto.InitializeStoreResult {
	return s.storeApp().InitializeStore(req)
}

func (s signerAdminServices) ChangeStorePassphrase(ctx context.Context, req adminproto.ChangeStorePassphraseRequest) adminproto.ChangeStorePassphraseResult {
	return s.storeApp().ChangeStorePassphrase(ctx, req)
}

func (s signerAdminServices) NewSessionIdentity(method string) *auth.Identity {
	return auth.NewProductIdentity(method)
}

func (s signerAdminServices) LogAuthorizationDenied(ctx adminserver.SessionContext, action auth.Action, resource auth.Resource, reason string) {
	if s.signer.auditLog == nil {
		return
	}
	s.signer.auditLog.LogAuthorizationDenied(ctx, action, resource, reason)
}

func (s signerAdminServices) EnrolledKeys() []protocol.EnrolledKeyInfo {
	ir := s.ProductRuntime()
	if ir == nil {
		return nil
	}
	connected := map[string]int{}
	if sshServer := s.signer.currentSSHServer(); sshServer != nil {
		connected = sshServer.ConnectedFingerprints()
	}
	entries := ir.EnrolledKeys()
	out := make([]protocol.EnrolledKeyInfo, 0, len(entries))
	for _, entry := range entries {
		out = append(out, protocol.EnrolledKeyInfo{
			Fingerprint: entry.Fingerprint,
			Label:       entry.Label,
			KeyType:     entry.Key.Type(),
			Connected:   connected[entry.Fingerprint] > 0,
		})
	}
	return out
}

func (s signerAdminServices) RevokeEnrolledKey(ctx adminserver.SessionContext, fingerprint string) (int, error) {
	return s.signer.RevokeClientKey(ctx, fingerprint)
}

func (s signerAdminServices) RevokeAllEnrolledKeys(ctx adminserver.SessionContext) (int, int, error) {
	return s.signer.RevokeAllClientKeys(ctx)
}

func (s signerAdminServices) PendingEnrollments() []protocol.PendingEnrollmentInfo {
	ir := s.ProductRuntime()
	if ir == nil {
		return nil
	}
	entries := ir.PendingEnrollments()
	out := make([]protocol.PendingEnrollmentInfo, 0, len(entries))
	for _, entry := range entries {
		out = append(out, protocol.PendingEnrollmentInfo{
			Fingerprint: entry.Fingerprint,
			Label:       entry.Label,
			KeyType:     entry.Key.Type(),
			RemoteAddr:  entry.RemoteAddr,
			RequestedAt: entry.RequestedAt.Unix(),
		})
	}
	return out
}

func (s signerAdminServices) ApproveEnrollment(ctx adminserver.SessionContext, fingerprint, label string) (string, error) {
	return s.signer.ApproveClientEnrollment(ctx, fingerprint, label)
}

func (s signerAdminServices) RejectEnrollment(ctx adminserver.SessionContext, fingerprint string) error {
	return s.signer.RejectClientEnrollment(ctx, fingerprint)
}

func (s signerAdminServices) ImportClientKey(ctx adminserver.SessionContext, publicKey, label string) (string, string, bool, error) {
	return s.signer.ImportClientKey(ctx, publicKey, label)
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
	// bound before an uncertain store-root replacement, including when this attempt
	// fails before promotion.
	defer s.daemon.rearmWatcherAfterGenerationFlip(ir)
	report, err := s.daemon.reconcileReloadAndPromote(ir, true)
	if err != nil {
		// reconcileReloadAndPromote entered recovery before it released the
		// store mutation lock.
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

// errReconcileStateChanged reports a reconcile that reloaded cleanly but
// found the runtime no longer in recovery when it went to promote it: a lock
// or another session's unlock came first, and that state stands.
var errReconcileStateChanged = errors.New("runtime state changed while store reconciliation completed")

// reconcileReloadAndPromote keeps strict validation, key publication, and the
// recovery-to-unlocked transition under one store mutation lock. This
// prevents a concurrent admin mutation from landing between validation and
// the runtime snapshot that authorizes signing.
//
// With enterRecoveryOnFailure (the explicit reconcile, which may start
// unlocked), a reconcile that fails enters recovery before the lock is
// released, the order recovery_binding.tla's ReloadFail with
// RecoveryBeforeRelease transcribes (RB2). The recovery-exit rescan passes
// false: it starts in recovery, so a failure leaves it there, and a lock
// that came in meanwhile stands (SetRecovery leaves a locked signer locked
// too, so this is belt and braces). A
// promotion refused after a clean reload (errReconcileStateChanged) enters
// no recovery either way.
func (s signerAdminServices) reconcileReloadAndPromote(ir *productruntime.Runtime, enterRecoveryOnFailure bool) (*signertemplates.ReloadReport, error) {
	var report *signertemplates.ReloadReport
	err := s.withStoreMutation(func() (err error) {
		report, err = s.reconcileLocked(ir, enterRecoveryOnFailure)
		return err
	})
	return report, err
}

// reconcileLocked is reconcileReloadAndPromote's work, run under the store
// mutation lock; it enters recovery on failure itself, so that happens
// before the lock is released.
func (s signerAdminServices) reconcileLocked(ir *productruntime.Runtime, enterRecoveryOnFailure bool) (report *signertemplates.ReloadReport, err error) {
	defer func() {
		if err != nil && enterRecoveryOnFailure && !errors.Is(err, errReconcileStateChanged) {
			ir.SetRecovery()
		}
	}()
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		return s.reconcileGenerationsLocked(ir, kr)
	}); err != nil {
		return nil, err
	}
	report, err = ir.Reload()
	if err != nil {
		return nil, fmt.Errorf("current generation failed credential reload: %w", err)
	}
	if ir.IsRecovery() && !ir.PromoteRecoveryToUnlocked() {
		return report, errReconcileStateChanged
	}
	return report, nil
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
	report, err := s.reconcileReloadAndPromote(ir, false)
	if err != nil {
		logInfof("staying in recovery mode: signer store failed reconciliation rescan: %v", err)
		return nil, false
	}
	if hub := s.signer.adminHub(); hub != nil {
		hub.NotifyStatus(ir.GetState().String(), ir.KeyCount(), ir.StatusAlerts())
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
	return adminproto.ListKeyTypesResult{KeyTypes: resp.KeyTypes}
}

func (s signerAdminServices) ListCosignerReferences() adminproto.ListCosignerReferencesResult {
	ir := s.ProductRuntime()
	var records []cosignerrefs.Record
	var invalid []cosignerrefs.InvalidRecord
	err := s.withStoreInspection(func() error {
		var err error
		records, invalid, err = cosignerrefs.List(ir.KeyPaths())
		return err
	})
	if err != nil {
		code, message := identityStoreInspectionError(err, "list_failed")
		return adminproto.ListCosignerReferencesResult{Code: code, Error: message}
	}
	result := adminproto.ListCosignerReferencesResult{References: make([]adminproto.CosignerReferenceInfo, len(records))}
	for i := range records {
		result.References[i] = adminCosignerReference(records[i])
	}
	for _, bad := range invalid {
		result.Invalid = append(result.Invalid, adminproto.InvalidCosignerReference{
			Path: bad.Path, Name: bad.Stem, Reason: bad.Reason, Removable: bad.Removable,
		})
	}
	return result
}

func (s signerAdminServices) GetCosignerReference(req adminproto.GetCosignerReferenceRequest) adminproto.GetCosignerReferenceResult {
	ir := s.ProductRuntime()
	var record cosignerrefs.Record
	var found bool
	err := s.withStoreInspection(func() error {
		var err error
		record, found, err = cosignerrefs.Get(ir.KeyPaths(), req.Name)
		return err
	})
	if err != nil {
		code, message := identityStoreInspectionError(err, "read_failed")
		return adminproto.GetCosignerReferenceResult{Code: code, Error: message}
	}
	if !found {
		return adminproto.GetCosignerReferenceResult{Code: "not_found", Error: fmt.Sprintf("cosigner reference %q not found", req.Name)}
	}
	return adminproto.GetCosignerReferenceResult{Success: true, Reference: adminCosignerReference(record)}
}

func (s signerAdminServices) ImportCosignerReference(req adminproto.ImportCosignerReferenceRequest) adminproto.ImportCosignerReferenceResult {
	ir := s.ProductRuntime()
	var record *cosignerrefs.Record
	err := s.withStoreMutation(func() error {
		var err error
		record, err = cosignerrefs.Import(ir.KeyPaths(), req.Name, []byte(req.EnvelopeJSON))
		return err
	})
	if err != nil {
		return adminproto.ImportCosignerReferenceResult{Code: "import_failed", Error: err.Error()}
	}
	return adminproto.ImportCosignerReferenceResult{Success: true, Reference: adminCosignerReference(*record)}
}

func (s signerAdminServices) RemoveCosignerReference(req adminproto.RemoveCosignerReferenceRequest) adminproto.RemoveCosignerReferenceResult {
	ir := s.ProductRuntime()
	var removal cosignerrefs.Removal
	err := s.withStoreMutation(func() error {
		var err error
		removal, err = cosignerrefs.Remove(ir.KeyPaths(), req.Name)
		return err
	})
	if err != nil {
		return adminproto.RemoveCosignerReferenceResult{Name: req.Name, Code: "remove_failed", Error: err.Error()}
	}
	return adminproto.RemoveCosignerReferenceResult{
		Success: true, Name: req.Name, ComponentKey: removal.ComponentKey, Removed: removal.Removed, Path: removal.Path,
	}
}

func (s signerAdminServices) ExportCosignerPublic(req adminproto.ExportCosignerPublicRequest) adminproto.ExportCosignerPublicResult {
	ir := s.ProductRuntime()
	componentKey, err := witness.NormalizeID(req.WitnessKeyID)
	if err != nil {
		return adminproto.ExportCosignerPublicResult{Code: "invalid_witness_key_id", Error: err.Error()}
	}
	var envelope witness.PublicReference
	var found bool
	err = s.withStoreInspection(func() error {
		active, err := ir.ActivePaths()
		if err != nil {
			return err
		}
		envelope, found, err = apkeys.ReadWitnessPublicMetadataActive(active, componentKey)
		return err
	})
	if err != nil {
		code, message := identityStoreInspectionError(err, "export_failed")
		return adminproto.ExportCosignerPublicResult{Code: code, Error: message}
	}
	if !found {
		return adminproto.ExportCosignerPublicResult{Code: "not_found", Error: fmt.Sprintf("cosigner public metadata for %s not found", componentKey)}
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return adminproto.ExportCosignerPublicResult{Code: "encode_failed", Error: err.Error()}
	}
	data = append(data, '\n')
	return adminproto.ExportCosignerPublicResult{Success: true, WitnessKeyID: componentKey, EnvelopeJSON: string(data)}
}

func (s signerAdminServices) ListGenerations() adminproto.GenerationInventory {
	ir := s.ProductRuntime()
	var report genstore.ReconcileReport
	var quarantined []genstore.QuarantineRecord
	err := s.withStoreInspection(func() error {
		return ir.WithKeyring(func(kr *crypto.Keyring) error {
			var err error
			report, err = genstore.InspectStoreRoot(ir.KeyPaths(), kr)
			if err != nil {
				return err
			}
			quarantined, err = genstore.ListQuarantined(ir.KeyPaths(), kr)
			return err
		})
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

func (s signerAdminServices) DiscardAbandonedGenerations(
	req adminproto.DiscardAbandonedGenerationsRequest,
) adminproto.DiscardAbandonedGenerationsResult {
	ir := s.ProductRuntime()
	var discarded []genstore.QuarantinePruneResult
	err := s.withStoreMutation(func() error {
		return ir.WithKeyring(func(kr *crypto.Keyring) error {
			var err error
			discarded, err = genstore.DiscardAbandoned(ir.KeyPaths(), req.GenerationIDs, kr)
			return err
		})
	})
	result := adminproto.DiscardAbandonedGenerationsResult{
		Discarded: make([]adminproto.PrunedQuarantinedGeneration, 0, len(discarded)),
	}
	for _, item := range discarded {
		result.Discarded = append(result.Discarded, adminproto.PrunedQuarantinedGeneration{
			GenerationID: item.GenerationID, EncodedBytes: item.EncodedBytes,
			AlreadyAbsent: item.AlreadyAbsent,
		})
	}
	if err != nil {
		result.Code = protocol.ResultCodeAbandonedDiscardFailed
		result.Error = err.Error()
		return result
	}
	result.Success = true
	return result
}

// ListDeletedArchive is a read-only inspection: like its siblings it does not
// run during a store mutation, answering retryable store_busy instead.
func (s signerAdminServices) ListDeletedArchive() adminproto.DeletedArchiveInventory {
	ir := s.ProductRuntime()
	var entries []genstore.DeletedArchiveEntry
	var usage genstore.DeletedArchiveUsage
	err := s.withStoreInspection(func() error {
		active, err := authenticatedSelection(ir)
		if err != nil {
			return err
		}
		entries, usage, err = genstore.ListDeletedArchive(active)
		return err
	})
	result := adminproto.DeletedArchiveInventory{
		Entries:    make([]adminproto.DeletedArchiveEntry, 0, len(entries)),
		EntryCount: usage.Entries, EncodedBytes: usage.EncodedBytes, Warning: usage.Warning(),
	}
	for _, entry := range entries {
		result.Entries = append(result.Entries, adminproto.DeletedArchiveEntry{Path: entry.Path, EncodedBytes: entry.EncodedBytes})
	}
	if err != nil {
		result.Code, result.Error = identityStoreInspectionError(err, protocol.ResultCodeArchiveListFailed)
	}
	return result
}

// authenticatedSelection returns the generation store-root.enc selects now,
// authenticated with the session keyring. Archive maintenance runs in recovery,
// where a failed reload can leave the runtime's cached generation behind the
// root, so it never acts on the cached binding. The selection is not
// content-validated: pruning an over-limit archive is how such a generation is
// repaired.
func authenticatedSelection(ir *productruntime.Runtime) (storepaths.GenPaths, error) {
	var active storepaths.GenPaths
	err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		var err error
		active, err = genstore.AuthenticateStoreRootSelection(ir.KeyPaths(), kr)
		return err
	})
	return active, err
}

func (s signerAdminServices) PruneDeletedArchive(req adminproto.PruneDeletedArchiveRequest) adminproto.PruneDeletedArchiveResult {
	ir := s.ProductRuntime()
	var pruned []genstore.DeletedArchivePruneResult
	err := s.withStoreMutation(func() error {
		active, err := authenticatedSelection(ir)
		if err != nil {
			return err
		}
		pruned, err = genstore.PruneDeletedArchive(active, req.Entries)
		return err
	})
	result := adminproto.PruneDeletedArchiveResult{Pruned: make([]adminproto.PrunedDeletedArchiveEntry, 0, len(pruned))}
	for _, item := range pruned {
		result.Pruned = append(result.Pruned, adminproto.PrunedDeletedArchiveEntry{
			Path: item.Path, EncodedBytes: item.EncodedBytes, AlreadyAbsent: item.AlreadyAbsent,
		})
	}
	if err != nil {
		result.Code = protocol.ResultCodeArchivePruneFailed
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
		TermVerified:         record.TermValidation.Verified,
		TermUnavailable:      record.TermValidation.TermUnavailable,
		TermFailed:           record.TermValidation.Failed,
	}
}

func (s signerAdminServices) withStoreMutation(fn func() error) error {
	return s.signer.withStoreMutation(fn)
}

func (s signerAdminServices) withStoreInspection(fn func() error) error {
	return s.signer.tryWithStoreInspection(fn)
}

func identityStoreInspectionError(err error, fallbackCode string) (string, string) {
	if errors.Is(err, errStoreBusy) {
		return protocol.ResultCodeStoreBusy, err.Error()
	}
	return fallbackCode, err.Error()
}

func adminCosignerReference(record cosignerrefs.Record) adminproto.CosignerReferenceInfo {
	return adminproto.CosignerReferenceInfo{
		Schema: record.Schema, Name: record.Name, ComponentKey: record.ComponentKey, KeyType: record.KeyType,
		PublicKeyHex: record.PublicKeyHex, ImportedAt: record.ImportedAt,
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
	return signeradmin.Service{Deps: signerAdminAppDeps(s), Runtime: s.ProductRuntime(), ASAChain: signerASAChain(s)}
}

// signerASAChain is the node's network mapping and its genesis-checked algod
// reads, for confirming assets into the ASA set.
type signerASAChain struct{ signer *Signer }

func (c signerASAChain) Networks() apconfig.GenesisHashNetworkResolver {
	return c.signer.genesisHashResolver()
}

func (c signerASAChain) ReadAsset(ctx context.Context, genesisHash []byte, assetID uint64) (models.AssetParams, error) {
	return c.signer.chainReader().ReadAsset(ctx, genesisHash, assetID)
}

func (s signerAdminServices) backupApp() backupadmin.Service {
	return backupadmin.Service{Deps: signerAdminAppDeps(s), Runtime: s.ProductRuntime()}
}

func (s signerAdminServices) backupServices() signerBackupServices {
	return signerBackupServices{Service: s.backupApp(), daemon: s}
}

func (s signerAdminServices) templateApp() templateadmin.Service {
	return templateadmin.Service{Deps: signerAdminAppDeps(s), Runtime: s.ProductRuntime()}
}

func (s signerAdminServices) templateServices() signerTemplateServices {
	return signerTemplateServices{Service: s.templateApp(), signer: s.signer}
}

func (s signerAdminServices) storeApp() storeadmin.Service {
	return storeadmin.Service{
		Deps:           signerAdminAppDeps(s),
		Runtime:        s.ProductRuntime(),
		AuditLog:       optionalAuditLog[storeadmin.AuditLogger](s.signer.auditLog),
		UnlockIdentity: s.UnlockIdentity,
	}
}

func (s signerAdminServices) keyApp() keyadmin.IPCService {
	return keyadmin.IPCService{
		Service: s.signer.restService().Deps.KeyAdmin,
		Logf:    logInfof,
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
	if bound, err := d.signer.productRuntime().ActiveKeyPaths(); err == nil {
		return bound
	}
	return d.signer.keyPaths
}

func (d signerAdminAppDeps) GenesisHashMappings() map[string]string {
	cfg := d.signer.ConfigSnapshot()
	return maps.Clone(cfg.GenesisHashNetworks)
}

func (d signerAdminAppDeps) SSHInfo() signeradmin.SSHInfo {
	cfg := d.signer.ConfigSnapshot()
	sshServer := d.signer.currentSSHServer()
	info := signeradmin.SSHInfo{Port: cfg.Endpoint.SSH.Port}
	if sshServer != nil {
		info.Clients = sshServer.ActiveConnectionCount()
		info.Fingerprint = sshServer.GetHostKeyFingerprint()
	}
	return info
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

func (d signerAdminAppDeps) Warnf(format string, args ...any) {
	logWarnf(format, args...)
}
