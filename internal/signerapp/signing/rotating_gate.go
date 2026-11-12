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
// to a rotating account this signer holds. A rotating account's address is
// its stage 0 program, a one-time stage key the rotating flow spends and
// retires on the account's own first spend. An account rekeyed to it would be
// stuck on that stage, outside any rotation, and every signature for it would
// reuse that one-time key. The rotating flow's own rekeys go to a stage
// address and pass. This is a signer invariant, not a policy setting. signed
// lists the zero-based positions this signer signs (signerPositions).
//
// It is a second line. Every rotating key type declares that it is not a
// valid rekey target and every rotating aplane key records that, so
// rejectRekeyToInvalidTarget, which runs first, refuses such a rekey at any
// position with rekey_target_not_valid. This check, which reads the key type
// rather than the record, fires only if a rotating aplane key's record ever
// said it is a valid rekey target.
//
// It takes the key snapshot only when a signed position rekeys an account to
// another address, which most requests never do.
func (s *Service) rejectRekeyToRotating(txns []types.Transaction, signed []int) *ServiceError {
	if s.Planner == nil || s.Planner.Snapshot == nil {
		return nil
	}
	var rekeys []int
	for _, i := range signed {
		if i < 0 || i >= len(txns) {
			return positionOutsideGroup(i, len(txns))
		}
		if txn := txns[i]; !txn.RekeyTo.IsZero() && txn.RekeyTo != txn.Sender {
			rekeys = append(rekeys, i)
		}
	}
	if len(rekeys) == 0 {
		return nil
	}
	keyTypes := s.Planner.Snapshot().KeyTypes
	for _, i := range rekeys {
		target := txns[i].RekeyTo.String()
		if rotatingkey.IsRotatingKeyType(keyTypes[target]) {
			return withTransactionIndex(i, forbidden(rotatingkey.RekeyTargetRefusal(target)))
		}
	}
	return nil
}
