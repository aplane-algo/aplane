// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// rejectRotatingKeyType refuses a rotating account on an ordinary signing
// path. Its authorizer changes on every spend and every signature must rekey
// to the next stage, so only the rotating flow may plan or sign for it. index
// is the zero-based slot.
func rejectRotatingKeyType(index int, keyType string) *ServiceError {
	if !rotatingkey.IsRotatingKeyType(keyType) {
		return nil
	}
	err := rotatingSigningRequired()
	err.Message = fmt.Sprintf("transaction %d: %s", index+1, err.Message)
	return err
}

// rejectRotatingComponentRequest refuses a component request that names a
// rotating account in any slot.
func (s *Service) rejectRotatingComponentRequest(req signerapi.ComponentRequest) *ServiceError {
	if s.Planner == nil || s.Planner.Snapshot == nil {
		return internal("planner not configured")
	}
	keyTypes := s.Planner.Snapshot().KeyTypes
	for i, slot := range req.GroupSignRequest().Requests {
		if err := rejectRotatingKeyType(i, keyTypes[slot.AuthAddress]); err != nil {
			return err
		}
	}
	return nil
}

// rejectRekeyToRotating refuses a signed position that rekeys another account
// to a rotating account this signer holds. A rotating account's address is
// its stage 0 program, a one-time authority the rotating flow spends and
// retires on the account's own first spend; an account rekeyed to it would be
// pinned to that stage, outside any rotation, and every signature for it
// would reuse a stage. The rotating flow's own rekeys go to a stage address
// and pass. This is a signer invariant, not a policy setting.
func (s *Service) rejectRekeyToRotating(txns []types.Transaction, evalCount int, passthroughIndices, foreignIndices map[int]bool) *ServiceError {
	if s.Planner == nil || s.Planner.Snapshot == nil {
		return nil
	}
	keyTypes := s.Planner.Snapshot().KeyTypes
	limit := evalCount
	if limit > len(txns) {
		limit = len(txns)
	}
	for i := 0; i < limit; i++ {
		txn := txns[i]
		if passthroughIndices[i] || foreignIndices[i] || txn.RekeyTo.IsZero() || txn.RekeyTo == txn.Sender {
			continue
		}
		target := txn.RekeyTo.String()
		if rotatingkey.IsRotatingKeyType(keyTypes[target]) {
			return forbidden(fmt.Sprintf("transaction %d: cannot rekey to %s: it is a rotating account, whose address authorizes only itself", i+1, target))
		}
	}
	return nil
}
