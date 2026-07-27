// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"errors"
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type activationPoint string

const (
	activationBeforeApply activationPoint = "before_apply"
	activationAfterEntry  activationPoint = "after_entry"
	activationAfterApply  activationPoint = "after_apply"
)

type activationInterruption struct {
	point activationPoint
	err   error
}

func (e *activationInterruption) Error() string {
	switch e.point {
	case activationBeforeApply:
		return fmt.Sprintf("activation interrupted before active writes: %v", e.err)
	case activationAfterEntry:
		return fmt.Sprintf("activation interrupted after active entry write: %v", e.err)
	default:
		return fmt.Sprintf("activation interrupted after active writes: %v", e.err)
	}
}

func (e *activationInterruption) Unwrap() error { return e.err }

type recoveredActivationError struct {
	code string
	err  error
}

func (e *recoveredActivationError) Error() string { return e.err.Error() }
func (e *recoveredActivationError) Unwrap() error { return e.err }

// ActivateRecovered applies one reviewed inactive batch to active storage.
// Durable rollback state is published before the first active-store write.
func (s Service) ActivateRecovered(
	ir *identity.Runtime,
	req adminproto.ActivateRecoveredRequest,
) adminproto.ActivateRecoveredResult {
	result := adminproto.ActivateRecoveredResult{RestoreID: req.RestoreID}
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		return s.activateRecovered(ir, req, &result)
	})
	if err != nil {
		var activationErr *recoveredActivationError
		if errors.As(err, &activationErr) {
			result.Code = activationErr.code
		} else {
			result.Code = protocol.ResultCodeRecoveredActivationFailed
		}
		result.Error = err.Error()
		return result
	}
	result.Success = true
	return result
}

func (s Service) activateRecovered(
	ir *identity.Runtime,
	req adminproto.ActivateRecoveredRequest,
	result *adminproto.ActivateRecoveredResult,
) error {
	if err := recovered.ValidateRestoreID(req.RestoreID); err != nil {
		return activationFailure(protocol.ResultCodeRecoveredActivationFailed, "%v", err)
	}
	// Generation-based stores commit activation with a durable pointer flip
	// (docs/ARCH_GENERATIONS.md); the journal/snapshot machinery below is
	// the legacy path, retained solely for unmigrated flat stores.
	generational, err := genstore.IsGenerational(s.Deps.KeyPaths(), ir.ID())
	if err != nil {
		return err
	}
	if generational {
		return s.activateRecoveredGenerational(ir, req, result)
	}
	// The scan over every batch is authoritative: an incomplete activation
	// anywhere blocks new activations, even for a different restore ID. Never
	// infer safety from the requested batch alone. [P1]
	incomplete, incompleteErr := recovered.IncompleteActivationIDs(s.Deps.KeyPaths(), ir.ID())
	if incompleteErr != nil {
		return fmt.Errorf("inspect activation recovery state: %w", incompleteErr)
	}
	for _, id := range incomplete {
		if id != req.RestoreID {
			return activationFailure(
				protocol.ResultCodeActivationIncomplete,
				"recovered batch %s has an incomplete activation; resolve it before activating another batch",
				id,
			)
		}
	}
	activationDir := s.Deps.KeyPaths().RecoveredActivationDir(ir.ID(), req.RestoreID)
	if _, err := os.Lstat(activationDir); err == nil {
		result.Resumed = true
		finished, keyCount, err := s.resumeRecoveredActivation(ir, req)
		if err != nil {
			return err
		}
		if finished {
			result.KeyCount = keyCount
			s.Deps.Logf("finished cleanup of completed recovered activation: %s", req.RestoreID)
			return nil
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect recovered activation state: %w", err)
	}

	var review adminproto.ReviewRecoveredResult
	err = ir.WithMasterKey(func(masterKey []byte) error {
		var reviewErr error
		review, reviewErr = s.reviewRecoveredWithMasterKey(ir, req.RestoreID, masterKey)
		return reviewErr
	})
	if err != nil {
		return fmt.Errorf("review recovered batch before activation: %w", err)
	}
	result.ArchiveSHA256 = review.ArchiveChecksum
	result.SourcePolicySHA256 = review.SourcePolicySHA256
	result.DestinationPolicySHA256 = review.DestinationPolicySHA256
	result.PolicyComparison = review.PolicyComparison
	result.ReplaceExisting = req.ReplaceExisting
	if req.ReviewToken == "" || req.ReviewToken != review.ReviewToken {
		return activationFailure(
			protocol.ResultCodeActivationReviewStale,
			"recovery review is stale; review restore %s again",
			req.RestoreID,
		)
	}
	if review.UnattendedSigningAckRequired &&
		!req.AcknowledgeUnattendedSigning {
		return activationFailure(
			protocol.ResultCodeActivationAckRequired,
			"unattended-signing acknowledgement is required",
		)
	}
	if len(review.ActiveConflicts) > 0 && !req.ReplaceExisting {
		return activationFailure(
			protocol.ResultCodeActivationConflict,
			"%d active credential conflict(s) require replace_existing",
			len(review.ActiveConflicts),
		)
	}

	snapshot, err := captureActivationSnapshot(s.Deps.KeyPaths(), ir.ID(), req.RestoreID)
	if err != nil {
		return fmt.Errorf("capture pre-activation state: %w", err)
	}
	defer snapshot.Zero()
	owned, err := snapshotOwnership(review.Entries)
	if err != nil {
		return fmt.Errorf("derive activation ownership: %w", err)
	}
	attachSnapshotOwnership(snapshot, owned)
	journal := recovered.ActivationJournal{
		RestoreID:                    req.RestoreID,
		State:                        recovered.ActivationApplying,
		ReviewToken:                  req.ReviewToken,
		DestinationPolicySHA256:      review.DestinationPolicySHA256,
		DestinationApprovalMode:      string(review.DestinationApprovalMode),
		AcknowledgeUnattendedSigning: req.AcknowledgeUnattendedSigning,
		ReplaceExisting:              req.ReplaceExisting,
	}
	if err := ir.WithMasterKey(func(masterKey []byte) error {
		return recovered.CreateActivation(
			s.Deps.KeyPaths(),
			ir.ID(),
			journal,
			*snapshot,
			masterKey,
		)
	}); err != nil {
		return fmt.Errorf("publish activation state: %w", err)
	}
	if err := s.runActivationHook(activationBeforeApply); err != nil {
		return err
	}

	applyErr := ir.WithMasterKey(func(masterKey []byte) error {
		return s.applyRecoveredBatch(ir, req, masterKey, &result.Warnings)
	})
	var interruption *activationInterruption
	if errors.As(applyErr, &interruption) {
		return interruption
	}
	if applyErr == nil {
		if err := s.runActivationHook(activationAfterApply); err != nil {
			return err
		}
	}
	if applyErr == nil {
		// Every active write must be durable before completion is recorded
		// and before any recovery evidence is removed. [P1c]
		if err := syncActiveNamespaces(s.Deps.KeyPaths(), ir.ID()); err != nil {
			applyErr = fmt.Errorf("sync activated namespaces: %w", err)
		}
	}
	var keyCount int
	if applyErr == nil {
		reloadReport, reloadErr := ir.Reload()
		if reloadErr != nil {
			applyErr = fmt.Errorf("reload activated identity: %w", reloadErr)
		} else if reloadReport != nil {
			keyCount = reloadReport.KeyCount
		}
	}
	if applyErr != nil {
		return s.rollbackFailedActivation(ir, req.RestoreID, snapshot, applyErr)
	}
	// The activation is applied, durable, and validated: record completion
	// durably so post-crash reconciliation finishes the cleanup instead of
	// rolling back a successful activation.
	if err := ir.WithMasterKey(func(masterKey []byte) error {
		return recovered.UpdateActivationState(
			s.Deps.KeyPaths(),
			ir.ID(),
			req.RestoreID,
			recovered.ActivationCompleted,
			masterKey,
		)
	}); err != nil {
		// Completion was never recorded, so exact rollback remains the
		// correct reconciliation, now or after a restart.
		return s.rollbackFailedActivation(ir, req.RestoreID, snapshot,
			fmt.Errorf("record activation completion: %w", err))
	}
	if err := recovered.RemoveBatch(s.Deps.KeyPaths(), ir.ID(), req.RestoreID); err != nil {
		// Never roll back after completion: the activation succeeded and
		// only cleanup remains. Retrying the activation finishes it.
		return activationFailure(
			protocol.ResultCodeRecoveredActivationFailed,
			"activation %s completed but cleanup failed; retry the activation to finish cleanup: %v",
			req.RestoreID,
			err,
		)
	}

	result.Activated = append([]adminproto.RecoveredReviewEntry(nil), review.Entries...)
	result.KeyCount = keyCount
	s.Deps.Logf("activated recovered backup batch: %s", req.RestoreID)
	return nil
}

// resumeRecoveredActivation reconciles an existing activation marker before
// a fresh activation may proceed. finished reports that the marker recorded a
// completed activation whose cleanup was finished here: the caller must not
// re-apply anything.
func (s Service) resumeRecoveredActivation(
	ir *identity.Runtime,
	req adminproto.ActivateRecoveredRequest,
) (finished bool, keyCount int, err error) {
	var (
		journal  *recovered.ActivationJournal
		snapshot *recovered.RollbackSnapshot
	)
	err = ir.WithMasterKey(func(masterKey []byte) error {
		var loadErr error
		journal, snapshot, loadErr = recovered.LoadActivation(
			s.Deps.KeyPaths(),
			ir.ID(),
			req.RestoreID,
			masterKey,
		)
		return loadErr
	})
	if err != nil {
		return false, 0, fmt.Errorf("load incomplete activation: %w", err)
	}
	defer snapshot.Zero()
	if journal.State == recovered.ActivationCompleted {
		// Every active write was durable and validated before completion was
		// recorded; only cleanup remains. Rolling back here would undo a
		// successful activation, so finish the cleanup regardless of how the
		// resume request compares to the recorded intent.
		reloadReport, reloadErr := ir.Reload()
		if reloadErr != nil {
			return false, 0, activationFailure(
				protocol.ResultCodeRecoveredActivationFailed,
				"reload completed activation %s: %v",
				req.RestoreID,
				reloadErr,
			)
		}
		if err := recovered.RemoveBatch(s.Deps.KeyPaths(), ir.ID(), req.RestoreID); err != nil {
			return false, 0, activationFailure(
				protocol.ResultCodeRecoveredActivationFailed,
				"finish cleanup of completed activation %s: %v",
				req.RestoreID,
				err,
			)
		}
		if reloadReport != nil {
			keyCount = reloadReport.KeyCount
		}
		return true, keyCount, nil
	}
	if journal.State != recovered.ActivationApplying {
		return false, 0, activationFailure(
			protocol.ResultCodeRecoveredRollbackFailed,
			"activation %s is rolling back; explicit rollback must finish first",
			req.RestoreID,
		)
	}
	if !activationRequestMatchesJournal(req, journal) {
		return false, 0, activationFailure(
			protocol.ResultCodeActivationReviewStale,
			"resume request does not match the recorded activation intent",
		)
	}
	if err := ir.WithMasterKey(func(masterKey []byte) error {
		return recovered.UpdateActivationState(
			s.Deps.KeyPaths(),
			ir.ID(),
			req.RestoreID,
			recovered.ActivationRollingBack,
			masterKey,
		)
	}); err != nil {
		return false, 0, fmt.Errorf("begin rollback-first activation resume: %w", err)
	}
	if err := restoreActivationSnapshot(s.Deps.KeyPaths(), ir.ID(), snapshot); err != nil {
		// The store may hold a partial mutation that was not reverted.
		// Signing must stop now, not at the next unlock. [P1b]
		ir.SetRecovery()
		return false, 0, activationFailure(
			protocol.ResultCodeRecoveredRollbackFailed,
			"restore prior state for activation resume: %v",
			err,
		)
	}
	if _, err := ir.Reload(); err != nil {
		ir.SetRecovery()
		return false, 0, activationFailure(
			protocol.ResultCodeRecoveredRollbackFailed,
			"reload prior state for activation resume: %v",
			err,
		)
	}
	if err := recovered.RemoveActivation(s.Deps.KeyPaths(), ir.ID(), req.RestoreID); err != nil {
		ir.SetRecovery()
		return false, 0, activationFailure(
			protocol.ResultCodeRecoveredRollbackFailed,
			"complete prior-state restoration for activation resume: %v",
			err,
		)
	}
	return false, 0, nil
}

func activationRequestMatchesJournal(
	req adminproto.ActivateRecoveredRequest,
	journal *recovered.ActivationJournal,
) bool {
	return journal != nil &&
		req.RestoreID == journal.RestoreID &&
		req.ReviewToken == journal.ReviewToken &&
		req.AcknowledgeUnattendedSigning == journal.AcknowledgeUnattendedSigning &&
		req.ReplaceExisting == journal.ReplaceExisting
}

func (s Service) applyRecoveredBatch(
	ir *identity.Runtime,
	req adminproto.ActivateRecoveredRequest,
	masterKey []byte,
	warnings *[]string,
) error {
	return s.applyRecoveredBatchTo(ir, req, masterKey, warnings, nil)
}

// applyRecoveredBatchTo applies the batch's entries; a non-nil target routes
// every namespace write into resolved active paths (e.g. a staged
// generation during a mint).
func (s Service) applyRecoveredBatchTo(
	ir *identity.Runtime,
	req adminproto.ActivateRecoveredRequest,
	masterKey []byte,
	warnings *[]string,
	target storepaths.ActivePaths,
) error {
	batch, err := recovered.LoadBatch(s.Deps.KeyPaths(), ir.ID(), req.RestoreID, masterKey)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(batch.SourcePolicyYAML)
	restorer := backup.NewRestorer(s.Deps.KeyPaths(), ir.ID()).
		WithNodeRole(ir.NodeRole()).
		WithOverwrite(req.ReplaceExisting).
		WithLogger(s.Deps.Logf).
		WithWarningHandler(func(_ string, warning string) {
			*warnings = append(*warnings, warning)
		})
	if target != nil {
		restorer = restorer.WithActiveNamespace(target)
	}
	for _, meta := range batch.Entries {
		entry, err := recovered.LoadEntry(
			s.Deps.KeyPaths(),
			ir.ID(),
			req.RestoreID,
			meta,
			masterKey,
		)
		if err != nil {
			return err
		}
		_, applyErr := restorer.ApplyRecoveredEntry(entry, masterKey)
		entry.ZeroSecrets()
		if applyErr != nil {
			return fmt.Errorf("apply recovered credential %s: %w", meta.Selector, applyErr)
		}
		if err := s.runActivationHook(activationAfterEntry); err != nil {
			return err
		}
	}
	return nil
}

func (s Service) runActivationHook(point activationPoint) error {
	if s.activationHook == nil {
		return nil
	}
	if err := s.activationHook(point); err != nil {
		return &activationInterruption{point: point, err: err}
	}
	return nil
}

func (s Service) rollbackFailedActivation(
	ir *identity.Runtime,
	restoreID string,
	snapshot *recovered.RollbackSnapshot,
	activationErr error,
) error {
	stateErr := ir.WithMasterKey(func(masterKey []byte) error {
		return recovered.UpdateActivationState(
			s.Deps.KeyPaths(),
			ir.ID(),
			restoreID,
			recovered.ActivationRollingBack,
			masterKey,
		)
	})
	restoreErr := restoreActivationSnapshot(s.Deps.KeyPaths(), ir.ID(), snapshot)
	var reloadErr error
	if restoreErr == nil {
		_, reloadErr = ir.Reload()
	}
	var cleanupErr error
	if stateErr == nil && restoreErr == nil && reloadErr == nil {
		cleanupErr = recovered.RemoveActivation(s.Deps.KeyPaths(), ir.ID(), restoreID)
	}
	reconciliationErr := errors.Join(stateErr, restoreErr, reloadErr, cleanupErr)
	if reconciliationErr != nil {
		// The active store may hold a partial mutation that automatic
		// rollback could not revert. Transition into recovery mode before
		// reporting the failure: signing must stop now, not at the next
		// unlock. [P1b]
		ir.SetRecovery()
		return activationFailure(
			protocol.ResultCodeRecoveredRollbackFailed,
			"activation failed: %v; automatic rollback is incomplete: %v",
			activationErr,
			reconciliationErr,
		)
	}
	return activationFailure(
		protocol.ResultCodeRecoveredActivationFailed,
		"activation failed and prior state was restored: %v",
		activationErr,
	)
}

func activationFailure(code, format string, args ...any) error {
	return &recoveredActivationError{
		code: code,
		err:  fmt.Errorf(format, args...),
	}
}

// RollbackRecovered explicitly restores the pre-activation state and leaves
// the inactive recovered batch available for a new review.
func (s Service) RollbackRecovered(
	ir *identity.Runtime,
	req adminproto.RollbackRecoveredRequest,
) adminproto.RollbackRecoveredResult {
	result := adminproto.RollbackRecoveredResult{RestoreID: req.RestoreID}
	mutated := false
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		if err := recovered.ValidateRestoreID(req.RestoreID); err != nil {
			return err
		}
		// Generation-based stores roll back a committed activation by
		// repointing CURRENT at its parent; there is no incomplete state.
		generational, err := genstore.IsGenerational(s.Deps.KeyPaths(), ir.ID())
		if err != nil {
			return err
		}
		if generational {
			return s.rollbackRecoveredGenerational(ir, req, &result)
		}
		var (
			journal  *recovered.ActivationJournal
			snapshot *recovered.RollbackSnapshot
		)
		err = ir.WithMasterKey(func(masterKey []byte) error {
			var loadErr error
			journal, snapshot, loadErr = recovered.LoadActivation(
				s.Deps.KeyPaths(),
				ir.ID(),
				req.RestoreID,
				masterKey,
			)
			if loadErr != nil {
				return loadErr
			}
			if journal.State == recovered.ActivationCompleted {
				// The activation succeeded; only cleanup remains. Rolling
				// back would revert a completed activation.
				return activationFailure(
					protocol.ResultCodeRecoveredActivationFailed,
					"activation %s already completed; retry the activation to finish cleanup instead of rolling back",
					req.RestoreID,
				)
			}
			if journal.State == recovered.ActivationApplying {
				return recovered.UpdateActivationState(
					s.Deps.KeyPaths(),
					ir.ID(),
					req.RestoreID,
					recovered.ActivationRollingBack,
					masterKey,
				)
			}
			return nil
		})
		if err != nil {
			if snapshot != nil {
				snapshot.Zero()
			}
			return err
		}
		defer snapshot.Zero()
		// From here on the active store is being mutated; a failure leaves
		// state that must force recovery mode. [P1b]
		mutated = true
		if err := restoreActivationSnapshot(s.Deps.KeyPaths(), ir.ID(), snapshot); err != nil {
			return err
		}
		reloadReport, err := ir.Reload()
		if err != nil {
			return err
		}
		if err := recovered.RemoveActivation(s.Deps.KeyPaths(), ir.ID(), req.RestoreID); err != nil {
			return err
		}
		if reloadReport != nil {
			result.KeyCount = reloadReport.KeyCount
		}
		return nil
	})
	if err != nil {
		if mutated {
			ir.SetRecovery()
		}
		var activationErr *recoveredActivationError
		if errors.As(err, &activationErr) {
			result.Code = activationErr.code
		} else {
			result.Code = protocol.ResultCodeRecoveredRollbackFailed
		}
		result.Error = err.Error()
		return result
	}
	result.Success = true
	s.Deps.Logf("rolled back incomplete recovered activation: %s", req.RestoreID)
	return result
}
