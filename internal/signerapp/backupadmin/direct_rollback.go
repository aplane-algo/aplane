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
	"github.com/aplane-algo/aplane/internal/rotationinventory"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
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

// RollbackRestore reconstructs the sealed parent content of the latest direct
// credential restore into a fresh current-term generation. It never rewinds
// CURRENT to historical ciphertext.
func (s Service) RollbackRestore(
	ir *identity.Runtime,
	req adminproto.RollbackRestoreRequest,
) adminproto.RollbackRestoreResult {
	result := adminproto.RollbackRestoreResult{OperationID: req.OperationID}
	if req.OperationID == "" {
		result.Code = protocol.ResultCodeRestoreRollbackRefused
		result.Error = "restore rollback requires an operation ID"
		return result
	}
	mutated := false
	err := s.Deps.WithIdentityMutation(ir.ID(), func() error {
		paths := s.Deps.KeyPaths()
		current, err := genstore.Resolve(paths, ir.ID())
		if err != nil {
			return err
		}
		manifest, err := genstore.ReadManifest(current)
		if err != nil {
			return err
		}
		if manifest.Operation != genstore.OperationCredentialRestore ||
			!manifest.RestoreRollbackEligible {
			return restoreFailure(
				protocol.ResultCodeRestoreRollbackRefused,
				"current generation %s was not produced by a rollback-eligible credential restore",
				current.GenerationID(),
			)
		}
		if manifest.ParentID == "" {
			return restoreFailure(
				protocol.ResultCodeRestoreRollbackRefused,
				"credential restore generation %s has no parent",
				current.GenerationID(),
			)
		}

		inventory, err := genstore.BuildInventory(current)
		if err != nil {
			return err
		}
		target := paths.GenerationPaths(ir.ID(), manifest.ParentID)
		var source *rollbackGenerationSource
		err = ir.WithKeyring(func(masterKey *crypto.Keyring) error {
			cutover, err := rotationinventory.EvaluateRollback(
				paths,
				ir.ID(),
				current.GenerationID(),
				inventory,
				manifest,
				masterKey,
			)
			if err != nil {
				return err
			}
			if cutover.Decision != rotationinventory.DecisionClean {
				return restoreFailure(
					protocol.ResultCodeRestoreRollbackDiverged,
					"generation %s changed after credential restore; rollback would discard later state",
					current.GenerationID(),
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
				Parent:                     current.GenerationID(),
				Operation:                  genstore.OperationCredentialRestoreRollback,
				OperationID:                req.OperationID,
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
			mutated = true
			result.GenerationID = generationID
			_, reconcileErr := rotationinventory.ReconcileBaselineForPreflight(
				paths, ir.ID(), generationID, masterKey,
			)
			return reconcileErr
		})
		if err != nil {
			visible, visibleErr := genstore.ReadCurrent(paths, ir.ID())
			if visibleErr == nil && visible == generationID {
				mutated = true
				result.GenerationID = generationID
			}
			if errors.Is(err, genstore.ErrCommitDurabilityUnknown) || mutated {
				ir.SetRecovery()
			}
			return err
		}
		report, err := ir.Reload()
		if err != nil {
			ir.SetRecovery()
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
		return result
	}
	result.Success = true
	s.Deps.Logf(
		"rolled back latest credential restore into generation %s",
		result.GenerationID,
	)
	return result
}
