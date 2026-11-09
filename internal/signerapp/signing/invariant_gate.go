// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// nonparticipationRefusal is why a nonparticipating keyreg is refused.
const nonparticipationRefusal = "a keyreg with nonparticipation is not supported: it permanently marks the account as unable to participate"

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
			continue
		}
		if txn := txns[i]; txn.Type == types.KeyRegistrationTx && txn.Nonparticipation {
			return forbidden(fmt.Sprintf("transaction %d: %s", i+1, nonparticipationRefusal))
		}
	}
	return nil
}

// signedPositions lists the client positions this signer signs on the signer
// role: the first evalCount, less passthrough and foreign ones.
func signedPositions(evalCount, groupLen int, passthroughIndices, foreignIndices map[int]bool) []int {
	limit := min(evalCount, groupLen)
	positions := make([]int, 0, limit)
	for i := 0; i < limit; i++ {
		if !passthroughIndices[i] && !foreignIndices[i] {
			positions = append(positions, i)
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
