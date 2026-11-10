// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func reviewTestAddress(first byte) types.Address {
	var address types.Address
	address[0] = first
	return address
}

func TestPluginReviewShowsEveryHandoverOfControlOrFunds(t *testing.T) {
	sender, other := reviewTestAddress(1), reviewTestAddress(2)

	cases := []struct {
		name string
		txn  types.Transaction
		want []string
	}{
		{
			name: "zero self-payment that rekeys",
			txn: types.Transaction{
				Type:             types.PaymentTx,
				Header:           types.Header{Sender: sender, RekeyTo: other},
				PaymentTxnFields: types.PaymentTxnFields{Receiver: sender},
			},
			want: []string{"pay 0 microAlgo -> " + sender.String(), "!! REKEY: control of " + sender.String() + " passes to " + other.String()},
		},
		{
			name: "payment that closes the account",
			txn: types.Transaction{
				Type:             types.PaymentTx,
				Header:           types.Header{Sender: sender},
				PaymentTxnFields: types.PaymentTxnFields{Receiver: sender, CloseRemainderTo: other},
			},
			want: []string{"!! CLOSE: the sender's whole ALGO balance -> " + other.String()},
		},
		{
			name: "asset transfer with close and clawback",
			txn: types.Transaction{
				Type:   types.AssetTransferTx,
				Header: types.Header{Sender: sender},
				AssetTransferTxnFields: types.AssetTransferTxnFields{
					XferAsset: 77, AssetAmount: 5, AssetReceiver: sender, AssetCloseTo: other, AssetSender: other,
				},
			},
			want: []string{
				"asset 77: transfer 5 base unit(s) -> " + sender.String(),
				"!! CLOSE: the sender's whole holding of asset 77 -> " + other.String(),
				"!! CLAWBACK: the asset is taken from " + other.String(),
			},
		},
		{
			name: "app call that rekeys",
			txn: types.Transaction{
				Type:   types.ApplicationCallTx,
				Header: types.Header{Sender: sender, RekeyTo: other},
				ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{
					ApplicationID: 9, OnCompletion: types.UpdateApplicationOC,
					ApplicationArgs: [][]byte{{1}}, ApprovalProgram: []byte{6, 0x81, 1}, ClearStateProgram: []byte{6, 0x81, 1},
				}},
			},
			want: []string{"appl id=9 (!! UpdateApplication)", "1 argument(s)", "!! carries program code", "!! REKEY"},
		},
		{
			name: "keyreg that rekeys",
			txn: types.Transaction{
				Type:   types.KeyRegistrationTx,
				Header: types.Header{Sender: sender, RekeyTo: other},
			},
			want: []string{"keyreg: go offline", "!! REKEY"},
		},
		{
			name: "asset destroy",
			txn: types.Transaction{
				Type:                 types.AssetConfigTx,
				Header:               types.Header{Sender: sender},
				AssetConfigTxnFields: types.AssetConfigTxnFields{ConfigAsset: 5},
			},
			want: []string{"!! asset 5: destroy"},
		},
		{
			name: "asset reconfigure",
			txn: types.Transaction{
				Type:   types.AssetConfigTx,
				Header: types.Header{Sender: sender},
				AssetConfigTxnFields: types.AssetConfigTxnFields{
					ConfigAsset: 5, AssetParams: types.AssetParams{Manager: other},
				},
			},
			want: []string{"asset 5: reconfigure", "manager=" + other.String() + " reserve=(none)"},
		},
		{
			name: "freeze",
			txn: types.Transaction{
				Type:   types.AssetFreezeTx,
				Header: types.Header{Sender: sender},
				AssetFreezeTxnFields: types.AssetFreezeTxnFields{
					FreezeAsset: 5, FreezeAccount: other, AssetFrozen: true,
				},
			},
			want: []string{"asset 5: freeze the holding of " + other.String()},
		},
		{
			name: "unknown type that rekeys",
			txn: types.Transaction{
				Type:   types.TxType("zzz"),
				Header: types.Header{Sender: sender, RekeyTo: other},
			},
			want: []string{`(type "zzz": details opaque to APlane)`, "!! REKEY"},
		},
	}
	for _, tc := range cases {
		got := strings.Join(pluginReviewLines(tc.txn), "\n")
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s: review missing %q:\n%s", tc.name, want, got)
			}
		}
	}

	plain := strings.Join(pluginReviewLines(types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: other, Amount: 5},
	}), "\n")
	if strings.Contains(plain, "!!") {
		t.Errorf("a plain payment is marked as a handover:\n%s", plain)
	}
}
