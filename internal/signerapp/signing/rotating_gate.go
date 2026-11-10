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

// rejectRekeyToRotating refuses a signed position that rekeys an account to a
// rotating account this signer holds, or to one of its stage addresses. A
// rotating account's address is its stage 0 program, and every stage address is
// a one-time key the rotating flow spends and retires. An account rekeyed to
// one would be stuck on that stage, outside any rotation, and every signature
// for it would reuse that one-time key.
//
// issued are the rekey targets the signer set itself and proved against the
// seed before this gate: a rotation's next stage. Only the rotating flow
// supplies any, and they are the one thing left out. The exception is tied to
// the flow, not to the sender: an ordinary request that rekeys a rotating
// account to one of its own stages is refused like any other.
//
// A stage address is known only once its table holds it. This is a signer
// invariant, not a policy setting. signed lists the zero-based positions this
// signer signs (signerPositions).
func (s *Service) rejectRekeyToRotating(txns []types.Transaction, signed []int, issued map[string]bool) *ServiceError {
	if s.Planner == nil || s.Planner.Snapshot == nil {
		return nil
	}
	keyTypes := s.Planner.Snapshot().KeyTypes
	stages := s.stageOwners()
	for _, i := range signed {
		if i < 0 || i >= len(txns) {
			return positionOutsideGroup(i, len(txns))
		}
		txn := txns[i]
		if txn.RekeyTo.IsZero() || txn.RekeyTo == txn.Sender {
			continue
		}
		target := txn.RekeyTo.String()
		if issued[target] {
			continue
		}
		if reason, refused := rotatingkey.RefuseRekeyTarget(target, keyTypes, stages); refused {
			return withTransactionIndex(i, forbidden(reason))
		}
	}
	return nil
}

// stageOwners looks an address up in the stage tables this process has open. A
// node without the rotating flow, such as a cosigner, has none.
func (s *Service) stageOwners() rotatingkey.StageOwners {
	if s.Rotating == nil || s.Rotating.Tables == nil {
		return nil
	}
	return s.Rotating.Tables.StageOwnersOf
}
