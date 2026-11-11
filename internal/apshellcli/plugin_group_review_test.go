// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/txnreview"
)

func reviewTestAddress(first byte) types.Address {
	var address types.Address
	address[0] = first
	return address
}

// The review of a slot is the signer's own description of the transaction,
// then every alert for it marked `!!`. What each transaction type's
// description says is tested where it is built, in internal/txnreview.
func TestPluginReviewIsTheSharedDescriptionPlusMarkedAlerts(t *testing.T) {
	sender, other := reviewTestAddress(1), reviewTestAddress(2)

	rekey := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender, RekeyTo: other},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: sender, CloseRemainderTo: other},
	}
	lines := pluginReviewLines(rekey)
	description := strings.Split(txnreview.Describe(rekey, txnreview.View{}), "\n")
	if len(lines) != len(description)+2 {
		t.Fatalf("review has %d line(s), want the %d description line(s) and 2 alerts:\n%s",
			len(lines), len(description), strings.Join(lines, "\n"))
	}
	for i, want := range description {
		if lines[i] != want {
			t.Errorf("line %d = %q, want the shared description's %q", i, lines[i], want)
		}
	}
	for i, alert := range txnreview.Alerts(rekey) {
		if got := lines[len(description)+i]; got != "!! "+alert {
			t.Errorf("alert line = %q, want %q", got, "!! "+alert)
		}
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{
		"!! REKEY: control of " + sender.String() + " passes to " + other.String(),
		"!! CLOSE: the sender's whole ALGO balance goes to " + other.String(),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("review missing %q:\n%s", want, got)
		}
	}

	plain := strings.Join(pluginReviewLines(types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: other, Amount: 5},
	}), "\n")
	if strings.Contains(plain, "!!") {
		t.Errorf("a plain payment carries an alert:\n%s", plain)
	}
	if !strings.Contains(plain, "Payment: 0.000005 ALGO") || !strings.Contains(plain, "To:   "+other.String()) {
		t.Errorf("a plain payment is not described:\n%s", plain)
	}
}

// A rekey is flagged whatever the transaction's type, including one the
// describer does not know.
func TestPluginReviewFlagsARekeyOnAnyType(t *testing.T) {
	sender, other := reviewTestAddress(1), reviewTestAddress(2)
	for _, txType := range []types.TxType{
		types.PaymentTx, types.AssetTransferTx, types.ApplicationCallTx,
		types.KeyRegistrationTx, types.AssetConfigTx, types.AssetFreezeTx, types.TxType("zzz"),
	} {
		got := strings.Join(pluginReviewLines(types.Transaction{
			Type: txType, Header: types.Header{Sender: sender, RekeyTo: other},
		}), "\n")
		if !strings.Contains(got, "!! REKEY: control of "+sender.String()+" passes to "+other.String()) {
			t.Errorf("type %q: the rekey is not flagged:\n%s", txType, got)
		}
	}
}

func TestPluginReviewEscapesThePluginsTransactionType(t *testing.T) {
	var out strings.Builder
	r := &REPLState{Out: &out}
	renderPluginGroupReview(r, "REVIEW", []pluginReviewSlot{{
		txn:  types.Transaction{Type: types.TxType("pay\x1b[2K\r  [1] forged"), Header: types.Header{Sender: reviewTestAddress(1)}},
		role: slotRolePluginSigned,
	}})
	if strings.ContainsAny(out.String(), "\x1b\r") {
		t.Fatalf("the review printed raw control bytes from the transaction type:\n%q", out.String())
	}
}
