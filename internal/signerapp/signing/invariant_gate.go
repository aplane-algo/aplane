// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
	"github.com/aplane-algo/aplane/internal/txnreview"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// nonparticipationRefusal is why a nonparticipating keyreg is refused.
const nonparticipationRefusal = "a keyreg with nonparticipation is not supported: it permanently marks the account as unable to participate"

// rekeyTargetNotValid refuses a rekey to target, an aplane key of keyType this
// signer holds that records it is not a valid rekey target. Its code is
// rekey_target_not_valid, which the message repeats for the audit log. For a
// rotating key type the message also says why such an account is no target:
// its address is a one-time stage key.
func rekeyTargetNotValid(target, keyType string) *ServiceError {
	message := signerapi.ErrCodeRekeyTargetNotValid + ": " + txnreview.RekeyTargetNotValidText(target, keyType) + " (valid_rekey_target: false)"
	if rotatingkey.IsRotatingKeyType(keyType) {
		message += "; " + rotatingkey.RekeyTargetReason
	}
	return &ServiceError{Kind: ErrorRekeyTargetNotValid, Message: message}
}

// rejectSignerInvariants runs every signer invariant, in order: no rekey to a
// held aplane key that is not a valid rekey target, no rekey to a rotating
// account, no nonparticipating keyreg. Both node roles call it before any
// policy verdict, so no policy can allow what an invariant refuses, and an
// invariant added here holds on both roles. txns is the whole group as it
// will go on chain, the signer's own dummies included, and signed lists the
// positions this node signs. The valid-target invariant judges every position
// of txns; the rotating and nonparticipation invariants judge the signed
// positions. Every rotating aplane key records that it is not a valid rekey
// target, so a rekey to a held rotating account meets the valid-target
// invariant first, at any position, and is refused with one code,
// rekey_target_not_valid; the rotating invariant stays as a second line.
// invalidRekeyTargets is the request's held addresses that are not valid
// rekey targets, from the key snapshot the request was planned with. On a
// cosigner, which holds no rotating accounts and no account aplane keys, the
// rekey target and rotating checks find nothing to refuse.
func (s *Service) rejectSignerInvariants(txns []types.Transaction, signed []int, invalidRekeyTargets map[string]txnreview.InvalidRekeyTarget) *ServiceError {
	if err := rejectRekeyToInvalidTarget(txns, invalidRekeyTargets); err != nil {
		return err
	}
	if err := s.rejectRekeyToRotating(txns, signed); err != nil {
		return err
	}
	return rejectNonparticipation(txns, signed)
}

// rejectRekeyToInvalidTarget refuses a group in which any transaction, at any
// position, rekeys an account to an address this signer holds an aplane key
// for, when that key records that it is not a valid rekey target
// (valid_rekey_target false, the value its key type declared when the key was
// created). It names the first such position, in its message and as the
// error's RefusedPosition, where the audit log records the refusal. The
// position may be one this signer signs, a passthrough, a foreign or
// contextual position: the signer puts no signature into a group that makes
// one of its own aplane keys that is not a valid rekey target an account's
// authority. For a rotating target that would mean every later signature for
// the account reuses a one-time stage key. invalid is those addresses, built
// from the key snapshot the request was planned with
// (invalidRekeyTargetsFromSnapshot), so the refusal and the rekeys rule judge
// one key set. The target may be the transaction's own sender: returning an
// account to its own address is no exception, since a rotating account's
// address, for one, is its one-time stage 0 key. It is a signer invariant,
// not a policy setting: no rekeys value and no rekey-to list lifts it. A
// foreign target, one this signer holds no aplane key for, is the rekeys
// setting's question, not this one's.
func rejectRekeyToInvalidTarget(txns []types.Transaction, invalid map[string]txnreview.InvalidRekeyTarget) *ServiceError {
	i, target, found, ok := txnreview.FirstRekeyToInvalidTarget(txns, invalid)
	if !ok {
		return nil
	}
	return withTransactionIndex(i, rekeyTargetNotValid(target, found.KeyType))
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
