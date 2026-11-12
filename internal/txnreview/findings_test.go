// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// The rekey finding says where the rekey hands the account and what this
// signer holds there, keeping "lose control" for an address it holds no aplane
// key for.
func TestRekeyFindingNamesWhatTheSignerHolds(t *testing.T) {
	sender, held, listed, unheld, protocol, htlc, rotating := types.Address{1}, types.Address{2}, types.Address{5}, types.Address{6}, types.Address{7}, types.Address{8}, types.Address{9}
	known := map[string]bool{sender.String(): true, held.String(): true, htlc.String(): true, rotating.String(): true}
	invalid := map[string]InvalidRekeyTarget{
		htlc.String():     {KeyType: "aplane.htlc.v1", GenericLogicSig: true},
		rotating.String(): {KeyType: "aplane.rotating-triple-wotsc.v1"},
	}
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
		{"held HTLC account", rekey(sender, htlc), FindingContext{KnownAddresses: known, InvalidRekeyTargets: invalid},
			RekeyTransfersText + "\n   >>> THIS SIGNER HOLDS THE APLANE KEY FOR THE NEW ADDRESS, BUT IT IS NOT A VALID REKEY TARGET (aplane.htlc.v1): AN ACCOUNT REKEYED TO IT MAY BE STRANDED <<<" +
				"\n   It is a generic LogicSig: its program decides what can be signed."},
		{"held rotating account", rekey(sender, rotating), FindingContext{KnownAddresses: known, InvalidRekeyTargets: invalid},
			line(RekeyTransfersText, RekeyHeldNotValidText(invalid[rotating.String()], false))},
		{"an HTLC account back to its own address", rekey(htlc, htlc), FindingContext{KnownAddresses: known, InvalidRekeyTargets: invalid},
			RekeyToOwnAddressText + "\n   >>> THIS SIGNER HOLDS THE APLANE KEY FOR THE ACCOUNT'S OWN ADDRESS, BUT IT IS NOT A VALID REKEY TARGET (aplane.htlc.v1): THE ACCOUNT MAY BE STRANDED <<<" +
				"\n   It is a generic LogicSig: its program decides what can be signed."},
		{"a rotating account back to its own address", rekey(rotating, rotating), FindingContext{KnownAddresses: known, InvalidRekeyTargets: invalid},
			line(RekeyToOwnAddressText, RekeyHeldNotValidText(invalid[rotating.String()], true))},
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

// The shared rule finds the first position that rekeys to a held aplane key
// that is not a valid rekey target, the transaction's own sender included,
// and ignores rekeys to any other address.
func TestFirstRekeyToInvalidTarget(t *testing.T) {
	held, other, foreign := types.Address{1}, types.Address{2}, types.Address{3}
	invalid := map[string]InvalidRekeyTarget{held.String(): {KeyType: "aplane.htlc.v1", GenericLogicSig: true}}
	txns := []types.Transaction{
		{Header: types.Header{Sender: other}},
		{Header: types.Header{Sender: other, RekeyTo: foreign}},
		{Header: types.Header{Sender: held, RekeyTo: held}},
		{Header: types.Header{Sender: other, RekeyTo: held}},
	}
	position, target, found, ok := FirstRekeyToInvalidTarget(txns, invalid)
	if !ok || position != 2 || target != held.String() || found.KeyType != "aplane.htlc.v1" || !found.GenericLogicSig {
		t.Fatalf("FirstRekeyToInvalidTarget() = %d, %q, %+v, %v; want position 2, the held target", position, target, found, ok)
	}
	if _, _, _, ok := FirstRekeyToInvalidTarget(txns[:2], invalid); ok {
		t.Fatal("a rekey to a foreign address was found")
	}
	if _, _, _, ok := FirstRekeyToInvalidTarget(txns, nil); ok {
		t.Fatal("an empty set found a target")
	}
}

func TestRekeyTargetNotValidText(t *testing.T) {
	if got, want := RekeyTargetNotValidText("ADDR", "aplane.htlc.v1"), "cannot rekey to ADDR: this signer holds its aplane key (aplane.htlc.v1), which is not a valid rekey target"; got != want {
		t.Errorf("RekeyTargetNotValidText() = %q, want %q", got, want)
	}
	if got := RekeyTargetNotValidText("ADDR", ""); !strings.Contains(got, "(unknown)") {
		t.Errorf("an empty key type is not read as unknown: %q", got)
	}
}
