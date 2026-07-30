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
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/rotationinventory"
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
	err := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		var reviewErr error
		review, reviewErr = s.reviewRecoveredWithKeyring(ir, req.RestoreID, masterKey)
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

	err = ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		if _, err := rotationinventory.ReconcileBaselineForPreflight(
			paths,
			ir.ID(),
			parent,
			masterKey,
		); err != nil {
			return fmt.Errorf("activation rotation baseline preflight: %w", err)
		}
		_, mintErr := genstore.Mint(paths, ir.ID(), genstore.MintRequest{
			GenerationID:      generationID,
			Parent:            parent,
			Operation:         "restore-activation",
			OperationID:       req.RestoreID + "-" + generationID,
			SourceRestoreID:   req.RestoreID,
			ReviewTokenSHA256: hex.EncodeToString(tokenDigest[:]),
			CreatedAt:         time.Now(),
			Integrity:         masterKey,
			Apply: func(staged storepaths.GenPaths) error {
				return s.applyRecoveredBatchTo(ir, req, masterKey, &result.Warnings, staged)
			},
		})
		if mintErr != nil {
			return mintErr
		}
		_, err := rotationinventory.ReconcileBaselineForPreflight(
			paths,
			ir.ID(),
			generationID,
			masterKey,
		)
		return err
	})
	if err != nil {
		visible, visibleErr := genstore.ReadCurrent(paths, ir.ID())
		if errors.Is(err, genstore.ErrCommitDurabilityUnknown) ||
			(visibleErr == nil && visible == generationID) {
			// The flip is visible: the activation IS committed for every
			// subsequent resolution, but its durability across a power loss
			// or its post-commit baseline cleanup is unconfirmed. Reload the
			// visible state and block signing until reconciliation confirms
			// the store.
			_, reloadErr := ir.Reload()
			ir.SetRecovery()
			return activationFailure(
				protocol.ResultCodeRecoveredRollbackFailed,
				"activation committed as generation %s but post-commit durability is unconfirmed; signing is blocked pending reconciliation (reload: %v): %v",
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
		rollbackErr := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
			return genstore.RollbackTo(paths, ir.ID(), parent, time.Now(), masterKey)
		})
		if rollbackErr != nil {
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
// by minting a fresh generation from its authenticated parent content. The
// content rolls back, but every encrypted member is freshly sealed under the
// current term and CURRENT never points back at a historical cryptographic
// epoch. Valid only when the current generation was minted from the requested
// batch; uncommitted attempts are discarded at unlock, never resumed.
func (s Service) rollbackRecoveredGenerational(
	ir *identity.Runtime,
	req adminproto.RollbackRecoveredRequest,
	result *adminproto.RollbackRecoveredResult,
	mutated *bool,
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
	// The current generation is mutable: a key generated or a template
	// installed after activation lives in this generation but is not part
	// of the restore. Rolling its content back would discard that state, so
	// compare it with the effective authenticated authority before staging
	// anything. A matching rotation baseline supersedes the at-mint
	// manifest; invalid or stale baseline data can never assert cleanness.
	inventory, err := genstore.BuildInventory(gen)
	if err != nil {
		return err
	}
	target := paths.GenerationPaths(ir.ID(), manifest.ParentID)
	var source *rollbackGenerationSource
	err = ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		cutover, err := rotationinventory.EvaluateRollback(
			paths,
			ir.ID(),
			gen.GenerationID(),
			inventory,
			manifest,
			masterKey,
		)
		if err != nil {
			return err
		}
		if cutover.Decision != rotationinventory.DecisionClean {
			return activationFailure(
				protocol.ResultCodeRecoveredRollbackDiverged,
				"generation %s no longer matches its effective rollback inventory: the store was mutated after activation of batch %s, and rolling back would discard those later changes; nothing was rolled back",
				gen.GenerationID(),
				req.RestoreID,
			)
		}
		if anchor, anchored := masterKey.HistoricalGenerationAnchor(
			target.GenerationID(),
		); anchored {
			if err := genstore.ValidateAnchoredSealed(target, anchor, masterKey); err != nil {
				return fmt.Errorf("rollback target: %w", err)
			}
		} else if err := genstore.ValidateSealed(target, masterKey); err != nil {
			return fmt.Errorf("rollback target: %w", err)
		}
		source, err = loadRollbackGenerationSource(target, masterKey)
		return err
	})
	if err != nil {
		return err
	}

	generationID, err := genstore.NewGenerationID(time.Now())
	if err != nil {
		return err
	}
	err = ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		_, mintErr := genstore.Mint(paths, ir.ID(), genstore.MintRequest{
			GenerationID:               generationID,
			Parent:                     gen.GenerationID(),
			Operation:                  "restore-rollback",
			OperationID:                req.RestoreID + "-" + generationID,
			RollbackSourceGenerationID: manifest.ParentID,
			CreatedAt:                  time.Now(),
			Integrity:                  masterKey,
			StartEmpty:                 true,
			Apply: func(staged storepaths.GenPaths) error {
				return populateRollbackGeneration(source, staged, masterKey)
			},
		})
		if mintErr != nil {
			return mintErr
		}
		// CURRENT now names generationID. The old baseline is stale and must
		// be removed durably after, never before, that commit.
		_, reconcileErr := rotationinventory.ReconcileBaselineForPreflight(
			paths,
			ir.ID(),
			generationID,
			masterKey,
		)
		return reconcileErr
	})
	if err != nil {
		current, currentErr := genstore.ReadCurrent(paths, ir.ID())
		if currentErr == nil && current == generationID {
			*mutated = true
		}
		if errors.Is(err, genstore.ErrCommitDurabilityUnknown) {
			ir.SetRecovery()
		}
		return err
	}
	*mutated = true
	reloadReport, err := ir.Reload()
	if err != nil {
		ir.SetRecovery()
		return fmt.Errorf(
			"rolled back into generation %s from source %s but reload failed: %w",
			generationID,
			manifest.ParentID,
			err,
		)
	}
	if reloadReport != nil {
		result.KeyCount = reloadReport.KeyCount
	}
	s.Deps.Logf(
		"rolled back activation of batch %s: minted generation %s from sealed source %s (outgoing %s)",
		req.RestoreID,
		generationID,
		manifest.ParentID,
		gen.GenerationID(),
	)
	return nil
}
