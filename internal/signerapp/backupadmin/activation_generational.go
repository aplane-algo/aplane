// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// activateRecoveredGenerational activates a reviewed batch on a
// generation-based store (docs/ARCH_GENERATIONS.md): the reviewed result is
// applied into a staged copy of the current generation and committed with
// one durable CURRENT flip. There is no journal, snapshot, marker, or resume
// path — a failure before the flip leaves nothing published (the staging
// directory is removed, the batch stays inactive), and a crash leaves at
// most an uncommitted generation that unlock-time reconciliation discards.
// The P1 family of partial-activation states is inexpressible here.
func (s Service) activateRecoveredGenerational(
	ir *identity.Runtime,
	req adminproto.ActivateRecoveredRequest,
	result *adminproto.ActivateRecoveredResult,
) error {
	var review adminproto.ReviewRecoveredResult
	err := ir.WithMasterKey(func(masterKey []byte) error {
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
	if review.UnattendedSigningAckRequired && !req.AcknowledgeUnattendedSigning {
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

	paths := s.Deps.KeyPaths()
	parent, err := genstore.ReadCurrent(paths, ir.ID())
	if err != nil {
		return fmt.Errorf("resolve current generation: %w", err)
	}
	generationID, err := genstore.NewGenerationID(time.Now())
	if err != nil {
		return err
	}
	tokenDigest := sha256.Sum256([]byte(req.ReviewToken))

	if _, err := genstore.Mint(paths, ir.ID(), genstore.MintRequest{
		GenerationID:      generationID,
		Parent:            parent,
		Operation:         "restore-activation",
		OperationID:       req.RestoreID + "-" + generationID,
		SourceRestoreID:   req.RestoreID,
		ReviewTokenSHA256: hex.EncodeToString(tokenDigest[:]),
		CreatedAt:         time.Now(),
		Apply: func(staged storepaths.GenPaths) error {
			return ir.WithMasterKey(func(masterKey []byte) error {
				return s.applyRecoveredBatchTo(ir, req, masterKey, &result.Warnings, staged)
			})
		},
	}); err != nil {
		if errors.Is(err, genstore.ErrCommitDurabilityUnknown) {
			// The flip is visible: the activation IS committed for every
			// subsequent resolution, but its durability across a power loss
			// is unproven. Reload the visible state and block signing until
			// reconciliation confirms the store.
			_, reloadErr := ir.Reload()
			ir.SetRecovery()
			return activationFailure(
				protocol.ResultCodeRecoveredRollbackFailed,
				"activation committed as generation %s but the commit's durability is unconfirmed; signing is blocked pending reconciliation (reload: %v): %v",
				generationID,
				reloadErr,
				err,
			)
		}
		return activationFailure(
			protocol.ResultCodeRecoveredActivationFailed,
			"activation failed; nothing was committed and the batch remains inactive: %v",
			err,
		)
	}

	// The commit is durable. Reload validates the new generation; a reload
	// failure rolls the pointer back to the parent — the exact pre-state.
	reloadReport, reloadErr := ir.Reload()
	if reloadErr != nil {
		if rollbackErr := genstore.RollbackTo(paths, ir.ID(), parent, time.Now()); rollbackErr != nil {
			ir.SetRecovery()
			return activationFailure(
				protocol.ResultCodeRecoveredRollbackFailed,
				"activated generation failed reload (%v) and pointer rollback failed: %v",
				reloadErr,
				rollbackErr,
			)
		}
		if _, err := ir.Reload(); err != nil {
			ir.SetRecovery()
			return activationFailure(
				protocol.ResultCodeRecoveredRollbackFailed,
				"activated generation failed reload (%v) and prior generation failed reload after rollback: %v",
				reloadErr,
				err,
			)
		}
		return activationFailure(
			protocol.ResultCodeRecoveredActivationFailed,
			"activation rolled back: activated generation failed reload: %v",
			reloadErr,
		)
	}
	var keyCount int
	if reloadReport != nil {
		keyCount = reloadReport.KeyCount
	}

	if err := recovered.RemoveBatch(paths, ir.ID(), req.RestoreID); err != nil {
		// The activation is committed and consistent; only the source batch
		// remains. Purge it explicitly.
		return activationFailure(
			protocol.ResultCodeRecoveredActivationFailed,
			"activation committed as generation %s but batch cleanup failed; purge batch %s manually: %v",
			generationID,
			req.RestoreID,
			err,
		)
	}

	result.Activated = append([]adminproto.RecoveredReviewEntry(nil), review.Entries...)
	result.KeyCount = keyCount
	s.Deps.Logf("activated recovered backup batch %s as generation %s", req.RestoreID, generationID)
	return nil
}

// rollbackRecoveredGenerational undoes the most recent committed activation
// by repointing CURRENT at its parent generation. Valid only when the
// current generation was minted from the requested batch; there are no
// incomplete activations on a generational store (uncommitted attempts are
// discarded at unlock, never resumed).
func (s Service) rollbackRecoveredGenerational(
	ir *identity.Runtime,
	req adminproto.RollbackRecoveredRequest,
	result *adminproto.RollbackRecoveredResult,
) error {
	paths := s.Deps.KeyPaths()
	gen, err := genstore.Resolve(paths, ir.ID())
	if err != nil {
		return err
	}
	manifest, err := genstore.ReadManifest(gen)
	if err != nil {
		return err
	}
	if manifest.SourceRestoreID != req.RestoreID {
		return fmt.Errorf(
			"no activation to roll back for batch %s: the current generation was produced by %s",
			req.RestoreID, manifest.Operation,
		)
	}
	if manifest.ParentID == "" {
		return fmt.Errorf("generation %s has no parent to roll back to", gen.GenerationID())
	}
	if err := genstore.RollbackTo(paths, ir.ID(), manifest.ParentID, time.Now()); err != nil {
		if errors.Is(err, genstore.ErrCommitDurabilityUnknown) {
			ir.SetRecovery()
		}
		return err
	}
	reloadReport, err := ir.Reload()
	if err != nil {
		ir.SetRecovery()
		return fmt.Errorf("rolled back to generation %s but reload failed: %w", manifest.ParentID, err)
	}
	if reloadReport != nil {
		result.KeyCount = reloadReport.KeyCount
	}
	s.Deps.Logf("rolled back activation of batch %s: CURRENT repointed from %s to %s",
		req.RestoreID, gen.GenerationID(), manifest.ParentID)
	return nil
}
