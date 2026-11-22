// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"errors"
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func restoreFailure(code, format string, args ...any) error {
	return &restoreRollbackError{code: code, err: fmt.Errorf(format, args...)}
}

type restoreRollbackError struct {
	code string
	err  error
}

func (e *restoreRollbackError) Error() string { return e.err.Error() }
func (e *restoreRollbackError) Unwrap() error { return e.err }

// RollbackRestore reconstructs active credential and key-type authority, with
// the per-key policies and source tokens, from the authenticated source named
// by the current manifest's rollback capability. It preserves the outgoing
// generation's deleted archive, node default policy and its source tokens, and
// node-role authority, and never selects historical ciphertext directly.
func (s Service) RollbackRestore(
	req adminproto.RollbackRestoreRequest,
) adminproto.RollbackRestoreResult {
	ir := s.Runtime
	result := adminproto.RollbackRestoreResult{OperationID: req.OperationID}
	if req.OperationID == "" {
		result.Code = protocol.ResultCodeRestoreRollbackRefused
		result.Error = "restore rollback requires an operation ID"
		return result
	}
	mutated := false
	err := s.Deps.WithStoreMutation(func() error {
		if err := ir.RequireUnlockedOrRecovery(); err != nil {
			return err
		}
		paths := s.Deps.KeyPaths()
		var generationID string
		err := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
			current, err := genstore.ResolveStoreRootWithKeyring(paths, masterKey)
			if err != nil {
				return err
			}
			manifest, err := genstore.ReadManifest(current)
			if err != nil {
				return err
			}
			capability := manifest.RollbackCapability
			if capability == nil {
				return restoreFailure(
					protocol.ResultCodeRestoreRollbackRefused,
					"current generation %s has no restore rollback capability",
					current.GenerationID(),
				)
			}
			inventory, err := genstore.BuildInventory(current)
			if err != nil {
				return err
			}
			clean, err := genstore.RollbackCapabilityMatches(capability, inventory)
			if err != nil {
				return err
			}
			if !clean {
				return restoreFailure(
					protocol.ResultCodeRestoreRollbackDiverged,
					"generation %s changed after its clean restore authority; rollback would discard later state",
					current.GenerationID(),
				)
			}
			target := paths.GenerationPaths(capability.SourceGenerationID)
			if anchor, anchored := masterKey.HistoricalGenerationAnchor(target.GenerationID()); anchored {
				if err := genstore.ValidateAnchoredSealed(target, anchor, masterKey); err != nil {
					return fmt.Errorf("rollback target: %w", err)
				}
			} else if err := genstore.ValidateSealed(target, masterKey); err != nil {
				return fmt.Errorf("rollback target: %w", err)
			}
			source, err := loadRollbackGenerationSource(target, masterKey)
			if err != nil {
				return err
			}

			generationID, err = genstore.NewGenerationID(time.Now())
			if err != nil {
				return err
			}
			// The successor does not record the source again: its ParentID
			// names current, whose manifest's rollback capability names it.
			_, mintErr := genstore.Mint(paths, genstore.MintRequest{
				GenerationID:      generationID,
				Parent:            current.GenerationID(),
				Operation:         genstore.OperationCredentialRestoreRollback,
				OperationID:       req.OperationID,
				CreatedAt:         time.Now(),
				Integrity:         masterKey,
				ValidateCandidate: storevalidate.StandardCandidate(paths, ir.NodeRole(), s.Deps.DataDir(), s.Deps.Config(), masterKey),
				Apply: func(staged storepaths.GenPaths) error {
					return populateRollbackGeneration(source, ir.NodeRole(), staged, masterKey)
				},
			})
			if mintErr != nil {
				return mintErr
			}
			mutated = true
			result.GenerationID = generationID
			return nil
		})
		if err != nil {
			if genstore.MintOutcomeOf(err) == genstore.Uncertain {
				mutated = true
				result.GenerationID = generationID
				result.CommitUncertain = true
				_, _ = ir.FollowCommit(genstore.Uncertain)
			}
			return err
		}
		report, err := ir.FollowCommit(genstore.Committed)
		if err != nil {
			return fmt.Errorf("restore rollback committed as generation %s but reload failed: %w", generationID, err)
		}
		if report != nil {
			result.KeyCount = report.KeyCount
		}
		return nil
	})
	if err != nil {
		var rollbackErr *restoreRollbackError
		switch {
		case errors.As(err, &rollbackErr):
			result.Code = rollbackErr.code
		case mutated:
			result.Code = protocol.ResultCodeRestoreRollbackFailed
		default:
			result.Code = protocol.ResultCodeRestoreRollbackRefused
		}
		result.Error = err.Error()
		if result.CommitUncertain {
			result.Error = fmt.Sprintf("rollback may have committed as generation %s; signing is blocked pending reconciliation: %v", result.GenerationID, err)
		}
		return result
	}
	result.Success = true
	s.Deps.Logf(
		"rolled back latest credential restore into generation %s",
		result.GenerationID,
	)
	return result
}
