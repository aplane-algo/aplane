// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"errors"
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/rotationinventory"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/testcheckpoint"
)

// RestoreBackup authenticates and validates an archive completely before
// committing its managed credentials through one generation transaction.
// Destination policy, templates, and key-type generation state are neither
// read from the archive nor changed by this operation.
func (s Service) RestoreBackup(
	req adminproto.RestoreBackupRequest,
) adminproto.RestoreBackupResult {
	ir := s.Runtime
	result := adminproto.RestoreBackupResult{OperationID: req.OperationID}
	passphrase := req.ExportPassphrase
	defer crypto.ZeroBytes(passphrase)
	if req.OperationID == "" {
		result.Code = protocol.ResultCodeRestoreFailed
		result.Error = "restore requires an operation ID"
		return result
	}
	archivePath, err := backup.ResolveManagedBackupPath(
		s.Deps.KeyPaths(), req.ArchivePath,
	)
	if err != nil {
		result.Code = protocol.ResultCodeRestoreFailed
		result.Error = err.Error()
		return result
	}
	limiter := s.Deps.RestoreLimiter()
	if retryAfter := limiter.RetryAfter(archivePath); retryAfter > 0 {
		result.Code = protocol.ResultCodeRestoreRateLimited
		result.Error = RestoreRateLimitedError(retryAfter)
		return result
	}

	wasRecovery := ir.IsRecovery()
	var parent, committedGeneration string
	archiveAuthenticated := false
	err = s.Deps.WithStoreMutation(func() error {
		prepareErr := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
			set, loadErr := backup.LoadManagedRestoreSet(
				s.Deps.KeyPaths(),

				archivePath,
				req.Addresses,
				passphrase,
				ir.NodeRole(),
			)
			if loadErr != nil {
				archiveAuthenticated = backup.ArchiveAuthenticated(loadErr)
				return loadErr
			}
			archiveAuthenticated = true
			defer set.ZeroSecrets()
			result.ArchiveSHA256 = set.ArchiveSHA256

			current, resolveErr := genstore.Resolve(s.Deps.KeyPaths())
			if resolveErr != nil {
				return fmt.Errorf("resolve current generation: %w", resolveErr)
			}
			if wasRecovery {
				if validateErr := genstore.ValidateCurrent(current); validateErr != nil {
					return fmt.Errorf("validate recovery-mode current generation: %w", validateErr)
				}
			}
			classification, classifyErr := backup.ClassifyRestoreSet(current, set, masterKey)
			if classifyErr != nil {
				return classifyErr
			}
			result.Identical = projectCredentialEntries(classification.Identical)
			result.Conflicts = projectRestoreConflicts(classification.Conflicts)
			if len(classification.Conflicts) > 0 && !req.ReplaceExisting {
				return restoreFailure(
					protocol.ResultCodeRestoreConflict,
					"%d credential conflict(s) require replace_existing",
					len(classification.Conflicts),
				)
			}
			if len(classification.Pending) == 0 {
				result.GenerationID = current.GenerationID()
				result.KeyCount = ir.KeyCount()
				return nil
			}

			parent = current.GenerationID()
			if _, reconcileErr := rotationinventory.ReconcileBaselineForPreflight(
				s.Deps.KeyPaths(), parent, masterKey,
			); reconcileErr != nil {
				return fmt.Errorf("restore rotation baseline preflight: %w", reconcileErr)
			}
			generationID, generationErr := genstore.NewGenerationID(time.Now())
			if generationErr != nil {
				return generationErr
			}
			_, mintErr := genstore.Mint(s.Deps.KeyPaths(), genstore.MintRequest{
				GenerationID:            generationID,
				Parent:                  parent,
				Operation:               genstore.OperationCredentialRestore,
				OperationID:             req.OperationID,
				RestoreArchiveSHA256:    set.ArchiveSHA256,
				RestoreRollbackEligible: !wasRecovery,
				CreatedAt:               time.Now(),
				Integrity:               masterKey,
				Apply: func(staged storepaths.GenPaths) error {
					for i := range classification.Pending {
						entry := classification.Pending[i]
						if applyErr := backup.ApplyCredentialEntry(
							staged, entry, masterKey, req.ReplaceExisting,
						); applyErr != nil {
							return fmt.Errorf("apply restored credential %s: %w", entry.Selector, applyErr)
						}
					}
					return nil
				},
			})
			if mintErr != nil {
				visible, visibleErr := genstore.ReadCurrent(s.Deps.KeyPaths())
				if errors.Is(mintErr, genstore.ErrCommitDurabilityUnknown) ||
					(visibleErr == nil && visible == generationID) {
					committedGeneration = generationID
					result.GenerationID = generationID
					result.CommitUncertain = true
					ir.SetRecovery()
					return restoreFailure(
						protocol.ResultCodeRestoreRollbackFailed,
						"restore committed as generation %s but durability is unconfirmed; signing is blocked pending reconciliation: %v",
						generationID, mintErr,
					)
				}
				return fmt.Errorf("restore failed before commit: %w", mintErr)
			}
			result.GenerationID = generationID
			committedGeneration = generationID
			result.Restored = projectCredentialEntries(classification.Pending)

			if _, reconcileErr := rotationinventory.ReconcileBaselineForPreflight(
				s.Deps.KeyPaths(), generationID, masterKey,
			); reconcileErr != nil {
				ir.SetRecovery()
				return restoreFailure(
					protocol.ResultCodeRestoreRollbackFailed,
					"restore committed as generation %s but rollback baseline reconciliation failed; signing is blocked pending reconciliation: %v",
					generationID, reconcileErr,
				)
			}
			return nil
		})
		if prepareErr != nil {
			// If publication may have occurred, reload the visible generation
			// outside WithKeyring so the keystore cache lock cannot self-deadlock.
			if committedGeneration != "" {
				_, _ = ir.Reload()
			}
			return prepareErr
		}
		if committedGeneration == "" {
			if !wasRecovery {
				return nil // canonical-plaintext idempotent no-op
			}
			report, reloadErr := ir.Reload()
			if reloadErr != nil {
				ir.SetRecovery()
				return restoreFailure(
					protocol.ResultCodeRecoveryBlocked,
					"idempotent restore left signing blocked because the current generation failed reload: %v",
					reloadErr,
				)
			}
			if report != nil {
				result.KeyCount = report.KeyCount
			}
			return nil
		}
		if checkpointErr := testcheckpoint.Reach("restore.current_flipped"); checkpointErr != nil {
			ir.SetRecovery()
			return restoreFailure(
				protocol.ResultCodeRestoreRollbackFailed,
				"restore committed as generation %s but cleanup was interrupted; signing is blocked pending reconciliation: %v",
				committedGeneration, checkpointErr,
			)
		}

		reloadErr := testcheckpoint.Reach("restore.reload_started")
		if reloadErr == nil {
			report, err := ir.Reload()
			reloadErr = err
			if report != nil {
				result.KeyCount = report.KeyCount
			}
		}
		if reloadErr == nil {
			return nil
		}
		rollbackErr := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
			return genstore.RollbackTo(
				s.Deps.KeyPaths(), parent, time.Now(), masterKey,
			)
		})
		if rollbackErr != nil {
			ir.SetRecovery()
			return restoreFailure(
				protocol.ResultCodeRestoreRollbackFailed,
				"restored generation failed reload (%v) and pointer rollback failed: %v",
				reloadErr, rollbackErr,
			)
		}
		if _, err := ir.Reload(); err != nil {
			ir.SetRecovery()
			return restoreFailure(
				protocol.ResultCodeRestoreRollbackFailed,
				"restored generation failed reload (%v) and prior generation failed reload after rollback: %v",
				reloadErr, err,
			)
		}
		return restoreFailure(
			protocol.ResultCodeRestoreFailed,
			"restore rolled back: restored generation failed reload: %v",
			reloadErr,
		)
	})
	if err != nil {
		if !archiveAuthenticated {
			limiter.RecordFailure(archivePath)
		}
		var restoreErr *restoreRollbackError
		if errors.As(err, &restoreErr) {
			result.Code = restoreErr.code
		} else {
			result.Code = protocol.ResultCodeRestoreFailed
		}
		result.Error = err.Error()
		return result
	}
	limiter.RecordSuccess(archivePath)
	result.Success = true
	s.Deps.Logf(
		"restored %d credential(s) from archive %s as generation %s",
		len(result.Restored), result.ArchiveSHA256, result.GenerationID,
	)
	return result
}

func projectCredentialEntries(entries []backup.CredentialEntry) []adminproto.RestoreCredential {
	result := make([]adminproto.RestoreCredential, len(entries))
	for i := range entries {
		result[i] = adminproto.RestoreCredential{
			Selector: entries[i].Selector,
			Category: entries[i].Category,
			KeyType:  entries[i].KeyType,
		}
	}
	return result
}

func projectRestoreConflicts(conflicts []backup.RestoreConflict) []adminproto.RestoreConflict {
	result := make([]adminproto.RestoreConflict, len(conflicts))
	for i := range conflicts {
		result[i] = adminproto.RestoreConflict{
			Selector:       conflicts[i].Selector,
			Category:       conflicts[i].Category,
			KeyType:        conflicts[i].KeyType,
			ExistingSHA256: conflicts[i].ExistingSHA256,
			Reason:         conflicts[i].Reason,
		}
	}
	return result
}
