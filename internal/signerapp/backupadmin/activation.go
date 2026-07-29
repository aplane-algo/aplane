// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/crypto"
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

// ActivateRecovered applies one reviewed inactive batch to active storage
// by minting a new generation; the commit is a single durable CURRENT flip,
// and rollback repoints CURRENT at the parent (docs/ARCH_GENERATIONS.md).
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
	return s.activateRecoveredGenerational(ir, req, result)
}

// applyRecoveredBatchTo applies the batch's entries; a non-nil target routes
// every namespace write into resolved active paths (e.g. a staged
// generation during a mint).
func (s Service) applyRecoveredBatchTo(
	ir *identity.Runtime,
	req adminproto.ActivateRecoveredRequest,
	masterKey *crypto.Keyring,
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
		return s.rollbackRecoveredGenerational(ir, req, &result, &mutated)
	})
	if err != nil {
		if mutated {
			ir.SetRecovery()
		}
		var activationErr *recoveredActivationError
		switch {
		case errors.As(err, &activationErr):
			result.Code = activationErr.code
		case mutated:
			result.Code = protocol.ResultCodeRecoveredRollbackFailed
		default:
			// Refused before any mutation: the store is unchanged and no
			// recovery was entered; the client must not lock into the
			// blocking recovery screen waiting for a push that never comes.
			result.Code = protocol.ResultCodeRecoveredRollbackRefused
		}
		result.Error = err.Error()
		return result
	}
	result.Success = true
	s.Deps.Logf("rolled back incomplete recovered activation: %s", req.RestoreID)
	return result
}
