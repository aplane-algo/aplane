// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// heldPosition is a position a request doesn't sign whose account this signer
// holds. A mixed cosigned group is signed in several requests, so each one
// carries the others' positions as context. The request's own fields call them
// foreign, which is right for what it signs and judges, and wrong as a statement
// of whose account it is: the reviewer sees the same group in each request.
//
// It changes what the review says, never what the request does. Such a position
// is still not signed and not judged by a policy here.
type heldPosition struct {
	// ListedRekeyTargets is the account's rekey-to list, when it has one. With
	// it the rekey warning can name a listed handover as one, as it does in the
	// request that signs the position.
	ListedRekeyTargets map[string]bool
}

// heldForeignPositions finds the foreign positions whose account this signer
// holds, from the signer's own records. holders names the key a position's
// request says authorizes it, when it says; otherwise the sender stands for the
// account. A client's word is not taken for it: an address the snapshot doesn't
// hold stays foreign.
//
// A position whose sender was rekeyed to an account this signer holds, and whose
// request doesn't name that account, is not recognised: the signer has no view
// of the chain here.
func heldForeignPositions(snapshot PlannerRuntimeSnapshot, txns []types.Transaction, foreign map[int]bool, holders map[int]string) map[int]*heldPosition {
	var held map[int]*heldPosition
	for i := range txns {
		if !foreign[i] {
			continue
		}
		holder := holders[i]
		if holder == "" {
			holder = txns[i].Sender.String()
		}
		if _, ok := snapshot.KeyFiles[holder]; !ok {
			continue
		}
		position := &heldPosition{}
		metadata := snapshot.KeyMetadata[holder]
		// A stored list that doesn't read leaves the position without one, and
		// the warning then speaks of an unlisted rekey, the more cautious text.
		if listed, err := listedRekeyTargets(metadata.BoundedAuthorization, metadata.Parameters); err == nil {
			position.ListedRekeyTargets = listed
		}
		if held == nil {
			held = make(map[int]*heldPosition)
		}
		held[i] = position
	}
	return held
}

// warningRekeyTargetsForPlan is each position's rekey-to list for the review's
// warnings, by index: the bounded positions this request signs, and the held
// positions it doesn't. Policy reads listedRekeyTargetsForPlan, which has only
// the first: a position this request doesn't sign has no policy here.
func warningRekeyTargetsForPlan(plan *PlanResult) map[int]map[string]bool {
	listed := listedRekeyTargetsForPlan(plan)
	if plan == nil {
		return listed
	}
	for i, position := range plan.HeldForeign {
		if position == nil || position.ListedRekeyTargets == nil {
			continue
		}
		if listed == nil {
			listed = make(map[int]map[string]bool)
		}
		listed[i] = position.ListedRekeyTargets
	}
	return listed
}
