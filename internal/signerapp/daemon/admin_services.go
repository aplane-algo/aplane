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
		Product:    svc,
		Settings:   svc.adminApp(),
		Keys:       svc.keyApp(),
		Backups:    svc.backupServices(),
		Templates:  svc.templateServices(),
		Inspection: svc,
		Authorizer: fs.authorizer,
		// Not optionalAuditLog: the session calls it unconditionally, and a nil
		// *AuditLogger refuses and drops as a daemon with no audit log should.
		Audit:       fs.auditLog,
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

func (s signerAdminServices) UnlockIdentity(ctx context.Context, passphrase []byte) (bool, int, string, string) {
	ir := s.ProductRuntime()
	// Reconciliation authenticates the sole store root before it relocates
	// or deletes residue. A valid root with damaged selected content still
	// opens the keyring and enters recovery; no generation is selected
	// heuristically.
	outcome, err := ir.Unlock(passphrase, func(kr *crypto.Keyring) error {
		return s.reconcileGenerationsLocked(ir, kr)
	}, func() {
		ir.EnsureKeyWatcher(startKeyWatcherForDir)
	})
	s.signer.recordUnlock(ctx, outcome, err)
	if err != nil {
		return failedUnlock(err)
	}
	logUnlockOutcome(outcome)
	if outcome.Recovery {
		return true, 0, "", protocol.ResultCodeRecoveryBlocked
	}
	return true, outcome.KeyCount, "", ""
}

// recordUnlock audits how an unlock request ended. One that found the signer
// unlocked changed nothing, so only its refusal is recorded.
func (fs *Signer) recordUnlock(ctx context.Context, outcome productruntime.UnlockOutcome, err error) {
	switch {
	case err != nil:
		fs.auditLog.LogIdentityUnlocked(ctx, "failed", 0, unlockFailureCode(err), err.Error())
	case outcome.Recovery:
		cause := ""
		if outcome.Cause != nil {
			cause = outcome.Cause.Error()
		}
		fs.auditLog.LogIdentityUnlocked(ctx, "recovery", 0, protocol.ResultCodeRecoveryBlocked, cause)
	case !outcome.AlreadyUnlocked:
		fs.auditLog.LogIdentityUnlocked(ctx, "unlocked", outcome.KeyCount, "", "")
	}
}

// logUnlockOutcome logs why an unlock request entered recovery, which its
// answer does not carry.
func logUnlockOutcome(outcome productruntime.UnlockOutcome) {
	if outcome.Recovery && outcome.Cause != nil {
		logWarnf("identity is recovery-blocked: %v", outcome.Cause)
	}
}

// failedUnlock answers an unlock that failed with err. A failure other than
// a wrong passphrase, such as a store root that cannot be opened, is logged
// with its cause; an unlock that lost a race to a lock is expected and
// logged below error.
func failedUnlock(err error) (bool, int, string, string) {
	code := unlockFailureCode(err)
	switch {
	case code != protocol.ErrCodeUnlockFailed:
	case errors.Is(err, signerruntime.ErrLockedDuringUnlock):
		logInfof("unlock did not complete: %v", err)
	default:
		logErrorf("unlock failed: %v", err)
	}
	return false, 0, err.Error(), code
}

// reconcileGenerationsLocked reconciles the store root with an open keyring:
// it authenticates the root, quarantines what it does not select, and
// validates the selected generation fail-closed. The caller holds the store
// mutation lock, across the reload and state change that follow: an unlock
// request, with the keyring its passphrase opened, or a reconcile.
func (s signerAdminServices) reconcileGenerationsLocked(ir *productruntime.Runtime, kr *crypto.Keyring) error {
	preview, err := genstore.InspectStoreRoot(ir.KeyPaths(), kr)
	if err != nil {
		return err
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
	report, err := genstore.ReconcileStoreRoot(ir.KeyPaths(), kr)
	for _, quarantined := range report.Quarantined {
		s.signer.auditLog.LogGenerationQuarantined(quarantined)
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

func unlockFailureCode(err error) string {
	if errors.Is(err, productruntime.ErrInvalidPassphrase) {
		return protocol.ErrCodeInvalidPassphrase
	}
	return protocol.ErrCodeUnlockFailed
}

func (s signerAdminServices) ChangeStorePassphrase(ctx context.Context, req adminproto.ChangeStorePassphraseRequest) adminproto.ChangeStorePassphraseResult {
	return s.storeApp().ChangeStorePassphrase(ctx, req)
}

func (s signerAdminServices) NewSessionIdentity(method string) *auth.Identity {
	return auth.NewProductIdentity(method)
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

func (s signerAdminServices) ImportClientKey(ctx adminserver.SessionContext, publicKey, label string) (adminserver.ImportedClientKey, error) {
	return s.signer.ImportClientKey(ctx, publicKey, label)
}

func restoreCommitted(result adminproto.RestoreBackupResult) bool {
	return len(result.Restored) > 0 || len(result.PoliciesRestored) > 0 || len(result.SourceTokensRestored) > 0
}

// finishBackupRecoveryExit runs the post-commit recovery-exit rescan after a
// restore or rollback succeeded while the signer was in recovery. When the
// rescan leaves the signer in recovery, it returns ResultCodeRecoveryBlocked
// and the formatted message; when a lock overtook the rescan, it leaves the
// caller's success answer intact with the signer locked.
func (s signerAdminServices) finishBackupRecoveryExit(
	ir *productruntime.Runtime,
	blockedMsg func(error) string,
) (report *signertemplates.ReloadReport, code, errMsg string) {
	report, err := s.exitRecoveryIfReconciled(ir)
	switch {
	case err == nil:
		return report, "", ""
	case ir.IsRecovery():
		return nil, protocol.ResultCodeRecoveryBlocked, blockedMsg(err)
	default:
		return nil, "", ""
	}
}

func (s signerBackupServices) RestoreBackup(req adminproto.RestoreBackupRequest) adminproto.RestoreBackupResult {
	ir := s.Runtime
	result := s.Service.RestoreBackup(req)
	if result.Success && ir.IsRecovery() {
		report, code, msg := s.daemon.finishBackupRecoveryExit(ir, func(err error) string {
			if restoreCommitted(result) {
				return fmt.Sprintf("restore committed as generation %s, but signer stayed in recovery mode: %v", result.GenerationID, err)
			}
			return fmt.Sprintf("restore made no changes, but signer stayed in recovery mode: %v", err)
		})
		if code != "" {
			result.Success = false
			result.Code = code
			result.Error = msg
		} else if report != nil {
			result.KeyCount = report.KeyCount
		}
	}
	ir.EnsureKeyWatcher(startKeyWatcherForDir)
	return result
}

func (s signerBackupServices) RollbackRestore(req adminproto.RollbackRestoreRequest) adminproto.RollbackRestoreResult {
	ir := s.Runtime
	result := s.Service.RollbackRestore(req)
	if result.Success && ir.IsRecovery() {
		// A rollback that runs in recovery publishes recovery's view, with no
		// keys; the reconcile that lifts recovery publishes them.
		report, code, msg := s.daemon.finishBackupRecoveryExit(ir, func(err error) string {
			return fmt.Sprintf("rollback committed as generation %s, but signer stayed in recovery mode: %v", result.GenerationID, err)
		})
		if code != "" {
			result.Success = false
			result.Code = code
			result.Error = msg
		} else if report != nil {
			result.KeyCount = report.KeyCount
		}
	}
	ir.EnsureKeyWatcher(startKeyWatcherForDir)
	return result
}

func (s signerBackupServices) ReconcileStore() adminproto.ReconcileStoreResult {
	ir := s.Runtime
	result := adminproto.ReconcileStoreResult{}
	// Leaving recovery needs a watcher, which an unlock that entered it did not
	// start, and a reload of the changes one saw meanwhile.
	defer ir.EnsureKeyWatcher(startKeyWatcherForDir)
	report, err := s.daemon.reconcileReloadAndPromote(ir, true)
	if err != nil {
		result.Error = err.Error()
		if errors.Is(err, productruntime.ErrNeitherUnlockedNorRecovery) {
			// Refused under the lock for a locked signer: nothing was
			// reconciled and no recovery was entered. The answer is the
			// handler's own for a locked signer, and names the state the
			// refusal found, whatever an unlock has published since.
			result.Code = protocol.ErrCodeSignerLocked
			result.State = signerruntime.SignerStateLocked.String()
			return result
		}
		if errors.Is(err, productruntime.ErrReconcileStateChanged) {
			// A lock overtook the reconcile; the lock stands.
			result.Code = protocol.ErrCodeSignerLocked
			result.State = ir.GetState().String()
			return result
		}
		// A reconcile that failed entered recovery before it released the
		// store mutation lock.
		result.Code = protocol.ResultCodeRecoveryBlocked
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
//
// With explicit (the explicit reconcile, which may start unlocked), a
// reconcile that fails enters recovery before the lock is released, the order
// recovery_binding.tla's ReloadFail with RecoveryBeforeRelease transcribes
// (RB2). The recovery-exit rescan passes false: it starts in recovery, so a
// failure leaves it there. A reconcile overtaken by a lock
// (productruntime.ErrReconcileStateChanged) leaves the lock standing
// (productruntime.Runtime.Reconcile).
func (s signerAdminServices) reconcileReloadAndPromote(ir *productruntime.Runtime, explicit bool) (*signertemplates.ReloadReport, error) {
	var report *signertemplates.ReloadReport
	err := s.withStoreMutation(func() (err error) {
		// The handler's state check ran before the request queued on the
		// lock; a lock since then leaves the keyring open until its cleanup
		// has run, and a reconcile there must not run.
		if err := ir.RequireUnlockedOrRecovery(); err != nil {
			return err
		}
		if !explicit && !ir.IsRecovery() {
			// A concurrent unlock or explicit reconcile already promoted the
			// signer out of recovery before this rescan acquired the lock; do
			// not run a non-explicit rescan on an unlocked signer.
			report = &signertemplates.ReloadReport{KeyCount: ir.KeyCount()}
			return nil
		}
		report, err = ir.Reconcile(func(kr *crypto.Keyring) error {
			return s.reconcileGenerationsLocked(ir, kr)
		}, explicit)
		return err
	})
	return report, err
}

// exitRecoveryIfReconciled promotes recovery only after the generation store
// reconciles and validates cleanly.
func (s signerAdminServices) exitRecoveryIfReconciled(ir *productruntime.Runtime) (*signertemplates.ReloadReport, error) {
	// The rescan re-runs generational reconciliation and fail-closed
	// validation of the selected generation; recovery only lifts when the
	// committed state proves clean.
	report, err := s.reconcileReloadAndPromote(ir, false)
	switch {
	case errors.Is(err, productruntime.ErrNeitherUnlockedNorRecovery):
		logInfof("reconciliation rescan skipped: %v", err)
		return nil, err
	case errors.Is(err, productruntime.ErrReconcileStateChanged):
		logInfof("reconciliation rescan overtaken by a lock: %v", err)
		return nil, err
	}
	if err != nil {
		logInfof("staying in recovery mode: signer store failed reconciliation rescan: %v", err)
		return nil, err
	}
	if hub := s.signer.adminHub(); hub != nil {
		hub.NotifyStatus(ir.GetState().String(), ir.KeyCount(), ir.StatusAlerts())
	}
	return report, nil
}

func (s signerTemplateServices) ListKeyTypes() adminproto.ListKeyTypesResult {
	ir := s.Runtime
	resp, err := s.signer.restService().KeyTypes(ir)
	if err != nil {
		return adminproto.ListKeyTypesResult{
			Code:  protocol.ResultCodeListFailed,
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
		code, message := identityStoreInspectionError(err, protocol.ResultCodeListFailed)
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
		code, message := identityStoreInspectionError(err, protocol.ResultCodeReadFailed)
		return adminproto.GetCosignerReferenceResult{Code: code, Error: message}
	}
	if !found {
		return adminproto.GetCosignerReferenceResult{Code: protocol.ResultCodeNotFound, Error: fmt.Sprintf("cosigner reference %q not found", req.Name)}
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
		return adminproto.ImportCosignerReferenceResult{Code: protocol.ResultCodeImportFailed, Error: err.Error()}
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
		return adminproto.RemoveCosignerReferenceResult{Name: req.Name, Code: protocol.ResultCodeRemoveFailed, Error: err.Error()}
	}
	return adminproto.RemoveCosignerReferenceResult{
		Success: true, Name: req.Name, ComponentKey: removal.ComponentKey, Removed: removal.Removed, Path: removal.Path,
	}
}

func (s signerAdminServices) ExportCosignerPublic(req adminproto.ExportCosignerPublicRequest) adminproto.ExportCosignerPublicResult {
	ir := s.ProductRuntime()
	componentKey, err := witness.NormalizeID(req.WitnessKeyID)
	if err != nil {
		return adminproto.ExportCosignerPublicResult{Code: protocol.ResultCodeInvalidWitnessKeyID, Error: err.Error()}
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
		code, message := identityStoreInspectionError(err, protocol.ResultCodeExportFailed)
		return adminproto.ExportCosignerPublicResult{Code: code, Error: message}
	}
	if !found {
		return adminproto.ExportCosignerPublicResult{Code: protocol.ResultCodeNotFound, Error: fmt.Sprintf("cosigner public metadata for %s not found", componentKey)}
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return adminproto.ExportCosignerPublicResult{Code: protocol.ResultCodeEncodeFailed, Error: err.Error()}
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
		code, message := identityStoreInspectionError(err, protocol.ResultCodeInspectFailed)
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

func (s signerAdminServices) adminApp() signeradmin.Service {
	return signeradmin.Service{
		Deps:     signerAdminAppDeps(s),
		Runtime:  s.ProductRuntime(),
		ASAChain: signerASAChain(s),
		Audit:    optionalAuditLog[signeradmin.SettingAudit](s.signer.auditLog),
	}
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
		Deps:     signerAdminAppDeps(s),
		Runtime:  s.ProductRuntime(),
		AuditLog: optionalAuditLog[storeadmin.AuditLogger](s.signer.auditLog),
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
