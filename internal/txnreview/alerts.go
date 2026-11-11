// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Alerts lists what a reviewer must not miss in txn: every way it hands over
// control or funds beyond its stated amount, whatever its type. A payment of
// zero to oneself that rekeys the account is a rekey. The description already
// shows each of these among its fields; the alerts pull them out so a review
// can lead with them.
//
// One rule decides each, the same one the description uses, so a review
// that shows both cannot have them disagree.
func Alerts(txn types.Transaction) []string {
	var alerts []string
	add := func(format string, args ...interface{}) {
		alerts = append(alerts, fmt.Sprintf(format, args...))
	}

	if !txn.RekeyTo.IsZero() {
		add("REKEY: control of %s passes to %s", txn.Sender.String(), txn.RekeyTo.String())
	}
	if !txn.CloseRemainderTo.IsZero() {
		add("CLOSE: the sender's whole ALGO balance goes to %s", txn.CloseRemainderTo.String())
	}
	if !txn.AssetCloseTo.IsZero() {
		add("CLOSE: the sender's whole holding of asset %d goes to %s", txn.XferAsset, txn.AssetCloseTo.String())
	}
	if isClawback(txn) {
		add("CLAWBACK: the asset is taken from %s, not from the sender", txn.AssetSender.String())
	}

	switch txn.Type {
	case types.ApplicationCallTx:
		switch txn.OnCompletion {
		case types.UpdateApplicationOC:
			add("APP UPDATE: replaces the program of app %d", txn.ApplicationID)
		case types.DeleteApplicationOC:
			add("APP DELETE: deletes app %d", txn.ApplicationID)
		}
	case types.AssetConfigTx:
		switch {
		case txn.ConfigAsset == 0:
		case txn.AssetParams.IsZero():
			add("ASSET DESTROY: destroys asset %d", txn.ConfigAsset)
		default:
			add("ASSET RECONFIGURE: sets who controls asset %d; a role set to none is gone for good", txn.ConfigAsset)
		}
	case types.KeyRegistrationTx:
		if txn.Nonparticipation {
			add("NONPARTICIPATION: marks the account nonparticipating, which cannot be undone")
		}
		if !isOfflineKeyReg(txn) && (txn.VotePK == (types.VotePK{}) || txn.SelectionPK == (types.VRFPK{})) {
			add("INCOMPLETE KEY REGISTRATION: a participation key is missing")
		}
	}
	return alerts
}

// isClawback reports whether an asset transfer takes from someone other than
// its sender.
func isClawback(txn types.Transaction) bool {
	return !txn.AssetSender.IsZero() && txn.AssetSender != txn.Sender
}

// isOfflineKeyReg reports whether a key registration carries no keys at all.
func isOfflineKeyReg(txn types.Transaction) bool {
	return txn.VotePK == (types.VotePK{}) && txn.SelectionPK == (types.VRFPK{})
}
