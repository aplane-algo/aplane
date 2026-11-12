// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// nonparticipationRefusal is why a nonparticipating keyreg is refused.
const nonparticipationRefusal = "a keyreg with nonparticipation is not supported: it permanently marks the account as unable to participate"

// rekeyTargetNotValid refuses a rekey to target, an aplane key of keyType this
// signer holds that records it is not a valid rekey target. Its code is
// rekey_target_not_valid, which the message repeats for the audit log.
func rekeyTargetNotValid(target, keyType string) *ServiceError {
	if keyType == "" {
		keyType = "unknown"
	}
	return &ServiceError{Kind: ErrorRekeyTargetNotValid, Message: signerapi.ErrCodeRekeyTargetNotValid + ": cannot rekey to " + target +
		": this signer holds its aplane key (" + keyType + "), which is not a valid rekey target (valid_rekey_target: false)"}
}

// rejectSignerInvariants runs every signer invariant over the positions this
// node signs. Both node roles call it before any policy verdict, so no policy
// can allow what an invariant refuses, and an invariant added here holds on
// both roles. On a cosigner, which holds no rotating accounts and no account
// aplane keys, the rotating and rekey target checks find nothing to refuse.
func (s *Service) rejectSignerInvariants(txns []types.Transaction, signed []int) *ServiceError {
	if err := s.rejectRekeyToRotating(txns, signed); err != nil {
		return err
	}
	if err := s.rejectRekeyToInvalidTarget(txns, signed); err != nil {
		return err
	}
	return rejectNonparticipation(txns, signed)
}

// rejectRekeyToInvalidTarget refuses a signed position that rekeys an
// account to an address this signer holds an aplane key for, when that key
// records that it is not a valid rekey target (valid_rekey_target false, the
// value its key type declared when the key was created): an account rekeyed
// there would be stranded, as one rekeyed to an HTLC account can only ever be
// closed to the HTLC's recipient or refund address. It is a signer invariant,
// not a policy setting: no rekeys value and no rekey-to list lifts it. A rekey
// of an account to its own address returns it to its own aplane key and
// passes, as rejectRekeyToRotating lets it. A foreign target, one this signer
// holds no aplane key for, is the rekeys setting's question, not this one's.
// A rotating target meets rejectRekeyToRotating first.
func (s *Service) rejectRekeyToInvalidTarget(txns []types.Transaction, signed []int) *ServiceError {
	if s.Planner == nil || s.Planner.Snapshot == nil {
		return nil
	}
	// Most requests rekey nothing: take the key snapshot only for one that
	// rekeys an account to another address.
	rekeys := false
	for _, i := range signed {
		if i < 0 || i >= len(txns) {
			return positionOutsideGroup(i, len(txns))
		}
		if txn := txns[i]; !txn.RekeyTo.IsZero() && txn.RekeyTo != txn.Sender {
			rekeys = true
		}
	}
	if !rekeys {
		return nil
	}
	snapshot := s.Planner.Snapshot()
	for _, i := range signed {
		txn := txns[i]
		if txn.RekeyTo.IsZero() || txn.RekeyTo == txn.Sender {
			continue
		}
		target := txn.RekeyTo.String()
		if _, held := snapshot.KeyFiles[target]; !held {
			continue
		}
		if snapshot.KeyMetadata[target].ValidRekeyTarget {
			continue
		}
		return withTransactionIndex(i, rekeyTargetNotValid(target, snapshot.KeyTypes[target]))
	}
	return nil
}

// positionOutsideGroup fails closed on a signed position the group doesn't
// have. Callers derive positions from the group, so it is a bug, never input.
func positionOutsideGroup(i, groupLen int) *ServiceError {
	return internal(fmt.Sprintf("signed position %d is outside a group of %d", i, groupLen))
}

// rejectNonparticipation refuses a keyreg with Nonparticipation set at a
// position this signer signs. Going nonparticipating can't be undone: the
// account can never register participation keys again, so it can never take
// part in consensus or earn its rewards. It is a signer invariant, checked
// before any policy verdict, so no policy can allow it, on either node role.
// signed lists the zero-based positions this signer signs; passthrough and
// foreign positions are not its signatures and are left out.
func rejectNonparticipation(txns []types.Transaction, signed []int) *ServiceError {
	for _, i := range signed {
		if i < 0 || i >= len(txns) {
			return positionOutsideGroup(i, len(txns))
		}
		if txn := txns[i]; txn.Type == types.KeyRegistrationTx && txn.Nonparticipation {
			return withTransactionIndex(i, forbidden(nonparticipationRefusal))
		}
	}
	return nil
}

// signerPositions lists the positions clientSlots classifies as this
// signer's signatures, so the signer invariants judge exactly the positions
// policy judges.
func signerPositions(slots []policyeval.Slot) []int {
	positions := make([]int, 0, len(slots))
	for _, slot := range slots {
		if slot.Class == policyeval.SlotSigner {
			positions = append(positions, slot.Index)
		}
	}
	return positions
}

// componentTargetPositions lists the positions a cosigner component request
// asks this cosigner to sign.
func componentTargetPositions(plan *ComponentSignPlan) []int {
	if plan == nil {
		return nil
	}
	positions := make([]int, len(plan.Targets))
	for i, target := range plan.Targets {
		positions[i] = target.TargetIndex
	}
	return positions
}
