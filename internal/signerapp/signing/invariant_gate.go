// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
	"github.com/aplane-algo/aplane/internal/txnreview"
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

// rejectSignerInvariants runs every signer invariant, in order: no rekey to a
// rotating account, no rekey to a held aplane key that is not a valid rekey
// target, no nonparticipating keyreg. Both node roles call it before any
// policy verdict, so no policy can allow what an invariant refuses, and an
// invariant added here holds on both roles. txns is the whole group as it
// will go on chain, the signer's own dummies included, and signed lists the
// positions this node signs. The rotating and nonparticipation invariants
// judge the signed positions; the valid-target invariant judges every
// position of txns. invalidRekeyTargets is the request's held addresses that
// are not valid rekey targets, from the key snapshot the request was planned
// with. On a cosigner, which holds no rotating accounts and no account aplane
// keys, the rotating and rekey target checks find nothing to refuse.
func (s *Service) rejectSignerInvariants(txns []types.Transaction, signed []int, invalidRekeyTargets map[string]txnreview.InvalidRekeyTarget) *ServiceError {
	if err := s.rejectRekeyToRotating(txns, signed); err != nil {
		return err
	}
	if err := rejectRekeyToInvalidTarget(txns, invalidRekeyTargets); err != nil {
		return err
	}
	return rejectNonparticipation(txns, signed)
}

// rejectRekeyToInvalidTarget refuses a group in which any transaction, at any
// position, rekeys an account to an address this signer holds an aplane key
// for, when that key records that it is not a valid rekey target
// (valid_rekey_target false, the value its key type declared when the key was
// created). It names the first such position. The position may be one this
// signer signs, a passthrough, a foreign or contextual position or a dummy:
// the signer puts no signature into a group that makes one of its own aplane
// keys that is not a valid rekey target an account's authority. For a
// rotating target that would mean every later signature for the account
// reuses a one-time stage key. invalid is those addresses, built from the key
// snapshot the request was planned with (invalidRekeyTargetsFromSnapshot), so
// the refusal and the rekeys rule judge one key set. The target may be the
// transaction's own sender: returning an account to its own address is no
// exception, since a rotating account's address, for one, is its one-time
// stage 0 key. It is a signer invariant, not a policy setting: no rekeys value
// and no rekey-to list lifts it. A foreign target, one this signer holds no
// aplane key for, is the rekeys setting's question, not this one's. A rotating
// target held for another account at a position this signer signs meets
// rejectRekeyToRotating first.
func rejectRekeyToInvalidTarget(txns []types.Transaction, invalid map[string]txnreview.InvalidRekeyTarget) *ServiceError {
	i := invalidRekeyTargetPosition(txns, invalid)
	if i < 0 {
		return nil
	}
	target := txns[i].RekeyTo.String()
	return withTransactionIndex(i, rekeyTargetNotValid(target, invalid[target].KeyType))
}

// invalidRekeyTargetPosition is the first position of txns that rekeys to an
// address in invalid, or -1 when none does: the position
// rejectRekeyToInvalidTarget names.
func invalidRekeyTargetPosition(txns []types.Transaction, invalid map[string]txnreview.InvalidRekeyTarget) int {
	if len(invalid) == 0 {
		return -1
	}
	for i, txn := range txns {
		if txn.RekeyTo.IsZero() {
			continue
		}
		if _, ok := invalid[txn.RekeyTo.String()]; ok {
			return i
		}
	}
	return -1
}

// refusedPosition is the position a signer-invariant refusal names when it
// may be one this signer does not sign: for a rekey_target_not_valid refusal,
// the position rejectRekeyToInvalidTarget named. It is -1 for every other
// refusal, which names a position this signer signs.
func refusedPosition(err *ServiceError, txns []types.Transaction, invalid map[string]txnreview.InvalidRekeyTarget) int {
	if err == nil || err.Kind != ErrorRekeyTargetNotValid {
		return -1
	}
	return invalidRekeyTargetPosition(txns, invalid)
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
