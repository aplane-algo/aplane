// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func detailsAddr(b byte) types.Address {
	var a types.Address
	for i := range a {
		a[i] = b
	}
	return a
}

func fieldNamed(t *testing.T, d Details, label string) Field {
	t.Helper()
	for _, f := range d.Fields {
		if f.Label == label {
			return f
		}
	}
	t.Fatalf("no field %q in %+v", label, d.Fields)
	return Field{}
}

// The fields name each account a transaction touches, and mark the lines the
// text warns of.
func TestDetailNamesPartiesAndAlerts(t *testing.T) {
	sender, receiver, closeTo, rekeyTo := detailsAddr(1), detailsAddr(2), detailsAddr(3), detailsAddr(4)
	txn := types.Transaction{Type: types.PaymentTx}
	txn.Sender, txn.Receiver, txn.Amount = sender, receiver, 5_000_000
	txn.CloseRemainderTo, txn.RekeyTo = closeTo, rekeyTo

	d := Detail(txn, View{})
	if d.Title != "Payment: 5.000000 ALGO" {
		t.Errorf("title = %q", d.Title)
	}
	for label, want := range map[string]types.Address{
		"From": sender, "To": receiver, "Close remainder to": closeTo, "REKEY TO": rekeyTo,
	} {
		f := fieldNamed(t, d, label)
		if f.Party != want.String() || f.Value != want.String() {
			t.Errorf("%s: party %q, value %q, want %s", label, f.Party, f.Value, want)
		}
		if f.Alert != (label == "REKEY TO") {
			t.Errorf("%s: alert = %t", label, f.Alert)
		}
	}
	if f := fieldNamed(t, d, "Fee"); f.Party != "" {
		t.Errorf("the fee names a party: %q", f.Party)
	}
}

// An asset role that is switched off is not a party.
func TestDetailOffAssetRoleIsNotAParty(t *testing.T) {
	txn := types.Transaction{Type: types.AssetConfigTx}
	txn.Sender = detailsAddr(1)
	txn.ConfigAsset = 7
	txn.AssetParams.Manager = detailsAddr(2)

	d := Detail(txn, View{})
	if f := fieldNamed(t, d, "Manager"); f.Party != detailsAddr(2).String() {
		t.Errorf("manager party = %q", f.Party)
	}
	if f := fieldNamed(t, d, "Clawback"); f.Party != "" || f.Value != "(zero address / disabled)" {
		t.Errorf("clawback = %+v", f)
	}
}

// List entries sit one level under the field that opens the list, and an
// account entry names its party.
func TestDetailListEntries(t *testing.T) {
	txn := types.Transaction{Type: types.ApplicationCallTx}
	txn.Sender = detailsAddr(1)
	txn.ApplicationID = 9
	txn.Accounts = []types.Address{detailsAddr(5)}

	d := Detail(txn, View{})
	for i, f := range d.Fields {
		if f.Label != "Accounts" {
			continue
		}
		entry := d.Fields[i+1]
		if entry.Depth != 1 || entry.Label != "[0]" || entry.Party != detailsAddr(5).String() {
			t.Errorf("entry = %+v", entry)
		}
		return
	}
	t.Fatal("no Accounts field")
}

// Describe is the printed form of Detail: one line for the title and one for
// each field, in order.
func TestDescribePrintsEveryField(t *testing.T) {
	txn := types.Transaction{Type: types.AssetTransferTx}
	txn.Sender, txn.AssetReceiver, txn.AssetSender = detailsAddr(1), detailsAddr(2), detailsAddr(3)
	txn.XferAsset, txn.AssetAmount = 31566704, 10
	txn.Note = []byte("memo")

	d := Detail(txn, View{Network: "testnet"})
	text := Describe(txn, View{Network: "testnet"})
	lines := strings.Split(text, "\n")
	if len(lines) != len(d.Fields)+1 || lines[0] != d.Title {
		t.Fatalf("%d lines for %d fields:\n%s", len(lines), len(d.Fields), text)
	}
	for i, f := range d.Fields {
		if !strings.Contains(lines[i+1], f.Value) || !strings.Contains(lines[i+1], f.Label) {
			t.Errorf("line %q does not carry field %+v", lines[i+1], f)
		}
	}
	if !strings.Contains(text, "\n  ⚠️  CLAWBACK FROM: "+detailsAddr(3).String()) {
		t.Errorf("clawback line changed:\n%s", text)
	}
	if !strings.Contains(text, "\n  To:   "+detailsAddr(2).String()) {
		t.Errorf("the To line is not lined up under From:\n%s", text)
	}
}
