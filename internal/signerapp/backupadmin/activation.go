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
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

type activationPoint string

const activationAfterApply activationPoint = "after_apply"

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
		return ir.WithMasterKey(func(masterKey []byte) error {
			return s.activateRecoveredWithMasterKey(ir, req, masterKey, &result)
		})
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

func (s Service) activateRecoveredWithMasterKey(
	ir *identity.Runtime,
	req adminproto.ActivateRecoveredRequest,
	masterKey []byte,
	result *adminproto.ActivateRecoveredResult,
) error {
	if err := recovered.ValidateRestoreID(req.RestoreID); err != nil {
		return activationFailure(protocol.ResultCodeRecoveredActivationFailed, "%v", err)
	}
	activationDir := s.Deps.KeyPaths().RecoveredActivationDir(ir.ID(), req.RestoreID)
	if _, err := os.Lstat(activationDir); err == nil {
		if err := s.resumeRecoveredActivation(ir, req, masterKey); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect recovered activation state: %w", err)
	}

	review, err := s.reviewRecoveredWithMasterKey(ir, req.RestoreID, masterKey)
	if err != nil {
		return fmt.Errorf("review recovered batch before activation: %w", err)
	}
	if req.ReviewToken == "" || req.ReviewToken != review.ReviewToken {
		return activationFailure(
			protocol.ResultCodeActivationReviewStale,
			"recovery review is stale; review restore %s again",
			req.RestoreID,
		)
	}
	if !req.AcknowledgePolicyTransition {
		return activationFailure(
			protocol.ResultCodeActivationAckRequired,
			"policy transition acknowledgement is required",
		)
	}
	if review.DestinationApprovalMode == adminproto.DestinationApprovalAutoApproveFallback &&
		!req.AcknowledgeUnattendedSigning {
		return activationFailure(
			protocol.ResultCodeActivationAckRequired,
			"unattended-signing acknowledgement is required for this destination",
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
	journal := recovered.ActivationJournal{
		RestoreID:                    req.RestoreID,
		State:                        recovered.ActivationApplying,
		ReviewToken:                  req.ReviewToken,
		DestinationPolicySHA256:      review.DestinationPolicySHA256,
		DestinationApprovalMode:      string(review.DestinationApprovalMode),
		AcknowledgePolicyTransition:  req.AcknowledgePolicyTransition,
		AcknowledgeUnattendedSigning: req.AcknowledgeUnattendedSigning,
		ReplaceExisting:              req.ReplaceExisting,
	}
	if err := recovered.CreateActivation(
		s.Deps.KeyPaths(),
		ir.ID(),
		journal,
		*snapshot,
		masterKey,
	); err != nil {
		return fmt.Errorf("publish activation state: %w", err)
	}

	applyErr := s.applyRecoveredBatch(ir, req, masterKey)
	if applyErr == nil && s.activationHook != nil {
		if err := s.activationHook(activationAfterApply); err != nil {
			return fmt.Errorf("activation interrupted after active writes: %w", err)
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
	if applyErr == nil {
		applyErr = recovered.RemoveBatch(s.Deps.KeyPaths(), ir.ID(), req.RestoreID)
		if applyErr != nil {
			applyErr = fmt.Errorf("complete recovered activation: %w", applyErr)
		}
	}
	if applyErr != nil {
		return s.rollbackFailedActivation(ir, req.RestoreID, snapshot, masterKey, applyErr)
	}

	result.Activated = append([]adminproto.RecoveredReviewEntry(nil), review.Entries...)
	result.KeyCount = keyCount
	s.Deps.Logf("activated recovered backup batch: %s", req.RestoreID)
	return nil
}

func (s Service) resumeRecoveredActivation(
	ir *identity.Runtime,
	req adminproto.ActivateRecoveredRequest,
	masterKey []byte,
) error {
	journal, snapshot, err := recovered.LoadActivation(
		s.Deps.KeyPaths(),
		ir.ID(),
		req.RestoreID,
		masterKey,
	)
	if err != nil {
		return fmt.Errorf("load incomplete activation: %w", err)
	}
	defer snapshot.Zero()
	if journal.State != recovered.ActivationApplying {
		return activationFailure(
			protocol.ResultCodeRecoveredRollbackFailed,
			"activation %s is rolling back; explicit rollback must finish first",
			req.RestoreID,
		)
	}
	if !activationRequestMatchesJournal(req, journal) {
		return activationFailure(
			protocol.ResultCodeActivationReviewStale,
			"resume request does not match the recorded activation intent",
		)
	}
	if err := recovered.UpdateActivationState(
		s.Deps.KeyPaths(),
		ir.ID(),
		req.RestoreID,
		recovered.ActivationRollingBack,
		masterKey,
	); err != nil {
		return fmt.Errorf("begin rollback-first activation resume: %w", err)
	}
	if err := restoreActivationSnapshot(s.Deps.KeyPaths(), ir.ID(), snapshot); err != nil {
		return activationFailure(
			protocol.ResultCodeRecoveredRollbackFailed,
			"restore prior state for activation resume: %v",
			err,
		)
	}
	if _, err := ir.Reload(); err != nil {
		return activationFailure(
			protocol.ResultCodeRecoveredRollbackFailed,
			"reload prior state for activation resume: %v",
			err,
		)
	}
	if err := recovered.RemoveActivation(s.Deps.KeyPaths(), ir.ID(), req.RestoreID); err != nil {
		return activationFailure(
			protocol.ResultCodeRecoveredRollbackFailed,
			"complete prior-state restoration for activation resume: %v",
			err,
		)
	}
	return nil
}

func activationRequestMatchesJournal(
	req adminproto.ActivateRecoveredRequest,
	journal *recovered.ActivationJournal,
) bool {
	return journal != nil &&
		req.RestoreID == journal.RestoreID &&
		req.ReviewToken == journal.ReviewToken &&
		req.AcknowledgePolicyTransition == journal.AcknowledgePolicyTransition &&
		req.AcknowledgeUnattendedSigning == journal.AcknowledgeUnattendedSigning &&
		req.ReplaceExisting == journal.ReplaceExisting
}

func (s Service) applyRecoveredBatch(
	ir *identity.Runtime,
	req adminproto.ActivateRecoveredRequest,
	masterKey []byte,
) error {
	batch, err := recovered.LoadBatch(s.Deps.KeyPaths(), ir.ID(), req.RestoreID, masterKey)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(batch.SourcePolicyYAML)
	restorer := backup.NewRestorer(s.Deps.KeyPaths(), ir.ID()).
		WithNodeRole(ir.NodeRole()).
		WithOverwrite(req.ReplaceExisting).
		WithLogger(s.Deps.Logf)
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
	}
	return nil
}

func (s Service) rollbackFailedActivation(
	ir *identity.Runtime,
	restoreID string,
	snapshot *recovered.RollbackSnapshot,
	masterKey []byte,
	activationErr error,
) error {
	stateErr := recovered.UpdateActivationState(
		s.Deps.KeyPaths(),
		ir.ID(),
		restoreID,
		recovered.ActivationRollingBack,
		masterKey,
	)
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
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		return ir.WithMasterKey(func(masterKey []byte) error {
			if err := recovered.ValidateRestoreID(req.RestoreID); err != nil {
				return err
			}
			journal, snapshot, err := recovered.LoadActivation(
				s.Deps.KeyPaths(),
				ir.ID(),
				req.RestoreID,
				masterKey,
			)
			if err != nil {
				return err
			}
			defer snapshot.Zero()
			if journal.State == recovered.ActivationApplying {
				if err := recovered.UpdateActivationState(
					s.Deps.KeyPaths(),
					ir.ID(),
					req.RestoreID,
					recovered.ActivationRollingBack,
					masterKey,
				); err != nil {
					return err
				}
			}
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
	})
	if err != nil {
		result.Code = protocol.ResultCodeRecoveredRollbackFailed
		result.Error = err.Error()
		return result
	}
	result.Success = true
	s.Deps.Logf("rolled back incomplete recovered activation: %s", req.RestoreID)
	return result
}
