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
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
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

	run := &restoreRun{
		s: s, req: req, result: &result, passphrase: passphrase, archivePath: archivePath,
		wasRecovery: ir.IsRecovery(), hints: make(map[string]backup.RotatingStageHint),
	}
	err = s.Deps.WithStoreMutation(run.mutate)
	if err != nil {
		if !run.archiveAuthenticated {
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

// restoreRun is one RestoreBackup call: what it was asked, and what it has
// learned and committed so far. Its methods run inside the store mutation.
type restoreRun struct {
	s           Service
	req         adminproto.RestoreBackupRequest
	result      *adminproto.RestoreBackupResult
	passphrase  []byte
	archivePath string
	// wasRecovery is whether the identity was recovery-blocked when the
	// restore began.
	wasRecovery bool
	// archiveAuthenticated is set once the archive's passphrase is proven,
	// after which a failure is not counted against the rate limit.
	archiveAuthenticated bool
	// committedGeneration is the generation the restore published, or empty
	// while nothing has been.
	committedGeneration string
	hints               map[string]backup.RotatingStageHint
}

// mutate is the whole store mutation: load and commit under the keyring,
// then bring the runtime up on what was committed. Every path that leaves
// the runtime behind the store root sets recovery before it returns, which
// is before the store lock is released.
func (r *restoreRun) mutate() (restoreErr error) {
	s, ir, result := r.s, r.s.Runtime, r.result
	defer func() {
		if restoreErr == nil {
			backup.PublishRotatingHints(ir.StageTables(), r.hints, s.Deps.Logf)
		}
	}()
	prepareErr := ir.WithKeyring(r.loadAndCommit)
	if prepareErr != nil {
		// If publication may have occurred, reload the visible generation
		// outside WithKeyring: a reload can zero the keyring, which waits
		// for the callbacks using it, this one included.
		if r.committedGeneration != "" {
			_, _ = ir.Reload()
		}
		return prepareErr
	}
	if r.committedGeneration == "" {
		if !r.wasRecovery {
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
	if checkpointErr := testcheckpoint.Reach("restore.store_root_replaced"); checkpointErr != nil {
		ir.SetRecovery()
		return restoreFailure(
			protocol.ResultCodeRestoreRollbackFailed,
			"restore committed as generation %s but cleanup was interrupted; signing is blocked pending reconciliation: %v",
			r.committedGeneration, checkpointErr,
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
	ir.SetRecovery()
	return restoreFailure(
		protocol.ResultCodeRestoreRollbackFailed,
		"restore committed as generation %s but runtime reload failed; signing is blocked pending recovery: %v",
		r.committedGeneration, reloadErr,
	)
}

// loadAndCommit authenticates the archive, classifies its entries against
// the current generation, and commits what is pending. It returns nil with
// nothing committed when the archive holds nothing new.
func (r *restoreRun) loadAndCommit(masterKey *crypto.Keyring) error {
	s, ir, result, req := r.s, r.s.Runtime, r.result, r.req
	set, loadErr := backup.LoadManagedRestoreSet(
		s.Deps.KeyPaths(),

		r.archivePath,
		req.Addresses,
		r.passphrase,
		ir.NodeRole(),
	)
	if loadErr != nil {
		r.archiveAuthenticated = backup.ArchiveAuthenticated(loadErr)
		return loadErr
	}
	r.archiveAuthenticated = true
	defer set.ZeroSecrets()
	for _, entry := range set.Entries {
		if entry.StageHint != nil {
			r.hints[entry.Selector] = *entry.StageHint
		}
	}
	result.ArchiveSHA256 = set.ArchiveSHA256

	current, resolveErr := genstore.ResolveStoreRootWithKeyring(s.Deps.KeyPaths(), masterKey)
	if resolveErr != nil {
		return fmt.Errorf("resolve current generation: %w", resolveErr)
	}
	if r.wasRecovery {
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
	if len(classification.Pending) == 0 && len(classification.Policies) == 0 {
		result.GenerationID = current.GenerationID()
		result.KeyCount = ir.KeyCount()
		return nil
	}
	if r.wasRecovery {
		repaired := make(map[string]bool, len(classification.Pending))
		for i := range classification.Pending {
			repaired[classification.Pending[i].Selector] = true
		}
		if validateErr := storevalidate.RecoveryDestination(storevalidate.Options{
			Paths: s.Deps.KeyPaths(), Candidate: current, Keyring: masterKey,
			ExpectedRole: ir.NodeRole(), DataDir: s.Deps.DataDir(), Config: s.Deps.Config(),
		}, repaired); validateErr != nil {
			return restoreFailure(
				protocol.ResultCodeRecoveryBlocked,
				"recovery restore refused because destination authority outside the authenticated credential selection is damaged: %v",
				validateErr,
			)
		}
	}
	return r.commit(current, set, classification, masterKey)
}

// commit mints the generation that holds the restored entries. A mint that
// may have replaced the store root without proving it durable sets recovery
// and reports the commit as uncertain.
func (r *restoreRun) commit(
	current storepaths.GenPaths,
	set *backup.RestoreSet,
	classification backup.RestoreClassification,
	masterKey *crypto.Keyring,
) error {
	s, ir, result, req := r.s, r.s.Runtime, r.result, r.req
	parent := current.GenerationID()
	generationID, generationErr := genstore.NewGenerationID(time.Now())
	if generationErr != nil {
		return generationErr
	}
	var rollbackCapability *genstore.RollbackCapability
	if !r.wasRecovery {
		rollbackCapability = genstore.NewRollbackCapabilitySeed(
			req.OperationID,
			set.ArchiveSHA256,
			parent,
		)
	}
	_, mintErr := genstore.Mint(s.Deps.KeyPaths(), genstore.MintRequest{
		GenerationID:       generationID,
		Parent:             parent,
		Operation:          genstore.OperationCredentialRestore,
		OperationID:        req.OperationID,
		RollbackCapability: rollbackCapability,
		CreatedAt:          time.Now(),
		Integrity:          masterKey,
		ValidateCandidate: func(staged storepaths.GenPaths) error {
			return storevalidate.Candidate(storevalidate.Options{
				Paths: s.Deps.KeyPaths(), Candidate: staged, Keyring: masterKey,
				ExpectedRole: ir.NodeRole(), DataDir: s.Deps.DataDir(), Config: s.Deps.Config(),
			})
		},
		Apply: func(staged storepaths.GenPaths) error {
			for i := range classification.Policies {
				entry := classification.Policies[i]
				if applyErr := backup.ApplyPolicyEntry(staged, ir.NodeRole(), entry, masterKey); applyErr != nil {
					return fmt.Errorf("apply restored policy %s: %w", entry.Selector, applyErr)
				}
			}
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
		visible, visibleErr := genstore.ResolveStoreRootWithKeyring(s.Deps.KeyPaths(), masterKey)
		if genstore.RootCommitUncertain(mintErr) ||
			(visibleErr == nil && visible.GenerationID() == generationID) {
			r.committedGeneration = generationID
			result.GenerationID = generationID
			result.CommitUncertain = true
			ir.SetRecovery()
			return restoreFailure(
				protocol.ResultCodeRestoreRollbackFailed,
				"restore may have committed as generation %s; signing is blocked pending reconciliation: %v",
				generationID, mintErr,
			)
		}
		return fmt.Errorf("restore failed before commit: %w", mintErr)
	}
	result.GenerationID = generationID
	r.committedGeneration = generationID
	result.Restored = projectCredentialEntries(classification.Pending)
	for _, entry := range classification.Policies {
		result.PoliciesRestored = append(result.PoliciesRestored, entry.Selector)
	}

	return nil
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
