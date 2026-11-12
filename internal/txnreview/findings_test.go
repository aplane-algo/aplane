// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// The rekey finding says where the rekey hands the account and what this
// signer holds there, keeping "lose control" for an address it holds no aplane
// key for.
func TestRekeyFindingNamesWhatTheSignerHolds(t *testing.T) {
	sender, held, listed, unheld, protocol := types.Address{1}, types.Address{2}, types.Address{5}, types.Address{6}, types.Address{7}
	known := map[string]bool{sender.String(): true, held.String(): true}
	line := func(first, second string) string { return first + "\n   " + second }
	rekey := func(from, to types.Address) types.Transaction {
		return types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: from, RekeyTo: to}}
	}
	for _, tc := range []struct {
		name string
		txn  types.Transaction
		ctx  FindingContext
		want string // "" for no finding
	}{
		{"held", rekey(sender, held), FindingContext{KnownAddresses: known}, line(RekeyTransfersText, RekeyHeldText)},
		{"own address, held", rekey(sender, sender), FindingContext{KnownAddresses: known}, line(RekeyToOwnAddressText, RekeyOwnAddressHeldText)},
		{"own address, not held", rekey(unheld, unheld), FindingContext{KnownAddresses: known}, line(RekeyToOwnAddressText, RekeyLoseControlText)},
		{"not held", rekey(sender, unheld), FindingContext{KnownAddresses: known}, line(RekeyTransfersText, RekeyLoseControlText)},
		{"listed, not held", rekey(sender, listed), FindingContext{KnownAddresses: known, ListedRekeyTargets: map[string]bool{listed.String(): true}},
			line(RekeyToListedTargetText, RekeyListedNotHeldText)},
		{"listed, held", rekey(sender, held), FindingContext{KnownAddresses: known, ListedRekeyTargets: map[string]bool{held.String(): true}},
			line(RekeyToListedTargetText, RekeyHeldText)},
		{"the signer's own protocol rekey", rekey(sender, protocol), FindingContext{KnownAddresses: known, ProtocolRekeyTargets: map[string]bool{protocol.String(): true}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			for _, finding := range Findings(tc.txn, tc.ctx) {
				if finding.Field == "RekeyTo" {
					got = finding.Message
				}
			}
			if got != tc.want {
				t.Fatalf("rekey finding = %q, want %q", got, tc.want)
			}
		})
	}
}
