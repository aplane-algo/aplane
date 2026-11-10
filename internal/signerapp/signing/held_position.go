// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// heldPosition is a position a request doesn't sign that this signer's own
// records connect to it. A mixed cosigned group is signed in several requests,
// so each one carries the others' positions as context. The request's own fields
// call them foreign, which is right for what it signs and judges, and wrong as a
// statement of whose they are: the reviewer sees the same group in each request.
//
// It changes what the review says, never what the request does. Such a position
// is still not signed and not judged by a policy here.
//
// The review says only what the signer knows. It knows which keys it holds. It
// does not read the chain here, so it doesn't know which key authorizes an
// account now.
type heldPosition struct {
	// SenderHeld is set when this signer holds the key of the position's sender.
	SenderHeld bool
	// ListedRekeyTargets is the sender's rekey-to list, when this signer holds
	// the sender, the account has a list, and the request names no other
	// authorizer. With it the rekey warning can name a listed handover as one,
	// as it does in the request that signs the position.
	ListedRekeyTargets map[string]bool
	// ListUnreadable is set when the held sender's stored list doesn't read. The
	// request that signs the position fails on it; this one says so.
	ListUnreadable bool
	// NamedAuthorizer is a key this signer holds that the request names as the
	// position's authorizer, for a sender that is another address. That the
	// sender was rekeyed to it is the request's word. The review says so, and
	// the warnings take nothing from it.
	NamedAuthorizer string
}

// heldForeignPositions finds the foreign positions this signer's records connect
// to it. The sender comes first: a sender whose key the snapshot holds is
// recognised whatever else the request says. holders names the key a position's
// request says authorizes it, when it says; a held key named for another sender
// is recorded as the request's claim. A position with neither stays foreign.
//
// A named authorizer other than the sender means, by the request's own account,
// that the sender's program doesn't authorize the position, so its rekey-to list
// isn't used.
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
		sender := txns[i].Sender.String()
		position := heldPosition{}
		_, position.SenderHeld = snapshot.KeyFiles[sender]
		if named := holders[i]; named != "" && named != sender {
			if _, ok := snapshot.KeyFiles[named]; ok {
				position.NamedAuthorizer = named
			}
		}
		if !position.SenderHeld && position.NamedAuthorizer == "" {
			continue
		}
		if position.SenderHeld && position.NamedAuthorizer == "" {
			metadata := snapshot.KeyMetadata[sender]
			listed, err := listedRekeyTargets(metadata.BoundedAuthorization, metadata.Parameters)
			if err != nil {
				// The warning then speaks of an unlisted rekey, the more
				// cautious text, and the review says the list didn't read.
				position.ListUnreadable = true
			} else {
				position.ListedRekeyTargets = listed
			}
		}
		if held == nil {
			held = make(map[int]*heldPosition)
		}
		held[i] = &position
	}
	return held
}

// heldPositionHeading is the review's heading for a held position, and the
// lines under it.
func heldPositionHeading(position *heldPosition) (label string, lines []string) {
	if position.NamedAuthorizer != "" {
		// The request's word, not the signer's: it holds the named key and
		// can't tell here that the sender was rekeyed to it.
		lines = append(lines, fmt.Sprintf("  Named authorizer: %s (this signer holds it; not checked against the chain)", position.NamedAuthorizer))
	}
	if position.ListUnreadable {
		lines = append(lines, "  This account's stored rekey-to list could not be read")
	}
	if position.SenderHeld {
		// Calling it foreign would contradict the request that signs it, which
		// shows the same group.
		return "THIS SIGNER HOLDS THIS ACCOUNT'S KEY - not signed in this request", lines
	}
	return "NOT SIGNED IN THIS REQUEST - authorizer named by the request", lines
}

// sendersHeld counts the positions whose sender's key this signer holds.
func sendersHeld(held map[int]*heldPosition) int {
	count := 0
	for _, position := range held {
		if position.SenderHeld {
			count++
		}
	}
	return count
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
		if position.ListedRekeyTargets == nil {
			continue
		}
		if listed == nil {
			listed = make(map[int]map[string]bool)
		}
		listed[i] = position.ListedRekeyTargets
	}
	return listed
}
