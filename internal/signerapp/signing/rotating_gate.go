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
	// A contextual position names its account outside the group request.
	for _, position := range req.ContextualPositions {
		if err := rejectRotatingKeyType(position.TargetIndex, keyTypes[position.AuthAddress]); err != nil {
			return err
		}
	}
	return nil
}

// rejectRekeyToRotating refuses a signed position that rekeys another account
// to a rotating account this signer holds, or to one of its stage addresses. A
// rotating account's address is its stage 0 program, and every stage address is
// a one-time key the rotating flow spends and retires. An account rekeyed to
// one would be stuck on that stage, outside any rotation, and every signature
// for it would reuse that one-time key. The rotating flow's own rekey goes to
// the account's next stage and passes: the rule (rotatingkey.RefuseRekeyTarget)
// leaves an account's rekey to its own stage alone. A stage address is known
// only once its table holds it. This is a signer invariant, not a policy
// setting. signed lists the zero-based positions this signer signs
// (signerPositions).
func (s *Service) rejectRekeyToRotating(txns []types.Transaction, signed []int) *ServiceError {
	if s.Planner == nil || s.Planner.Snapshot == nil {
		return nil
	}
	keyTypes := s.Planner.Snapshot().KeyTypes
	stages := s.stageOwner()
	for _, i := range signed {
		if i < 0 || i >= len(txns) {
			return positionOutsideGroup(i, len(txns))
		}
		txn := txns[i]
		if txn.RekeyTo.IsZero() || txn.RekeyTo == txn.Sender {
			continue
		}
		if reason, refused := rotatingkey.RefuseRekeyTarget(txn.Sender.String(), txn.RekeyTo.String(), keyTypes, stages); refused {
			return withTransactionIndex(i, forbidden(reason))
		}
	}
	return nil
}

// stageOwner looks an address up in the stage tables this process has open. A
// node without the rotating flow, such as a cosigner, has none.
func (s *Service) stageOwner() rotatingkey.StageOwner {
	if s.Rotating == nil || s.Rotating.Tables == nil {
		return nil
	}
	return s.Rotating.Tables.StageOwnerOf
}
