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
			name: "app call lists what it reaches",
			txn: types.Transaction{
				Type:   types.ApplicationCallTx,
				Header: types.Header{Sender: sender},
				ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{
					ApplicationID: 9, Accounts: []types.Address{other}, ForeignApps: []types.AppIndex{44},
					ForeignAssets: []types.AssetIndex{55},
					BoxReferences: []types.BoxReference{{ForeignAppIdx: 1, Name: []byte("b\x1b[2J")}},
					Access: []types.ResourceRef{
						{Address: other}, {Asset: 55}, {Holding: types.HoldingRef{Address: 1, Asset: 2}}, {},
						{Holding: types.HoldingRef{Address: 40, Asset: 1}},
						{Box: types.BoxReference{Name: []byte("own")}},
					},
					RejectVersion: 3,
				}},
			},
			want: []string{
				"account[0]: " + other.String(), "app[0]: 44", "asset[0]: 55",
				`box[0]: app[0] = 44, name "b\x1b[2J"`,
				"access[0]: account " + other.String(), "access[1]: asset 55",
				"access[2]: holding of access[1] by access[0]",
				"access[4]: holding of ?access[0] (not an asset) by ?access[39] (no such entry)",
				"access[5]: box of the called app 9, name \"own\"",
				"access[3]: (empty entry: adds box read/write budget)",
				"reject version 3",
			},
		},
		{
			name: "keyreg online shows its keys",
			txn: types.Transaction{
				Type:   types.KeyRegistrationTx,
				Header: types.Header{Sender: sender},
				KeyregTxnFields: types.KeyregTxnFields{
					VotePK: types.VotePK{1}, SelectionPK: types.VRFPK{2}, VoteFirst: 5, VoteLast: 9, VoteKeyDilution: 3,
				},
			},
			want: []string{"keyreg: go online, votes valid 5-9, key dilution 3", "vote key AQAA", "selection key AgAA", "state proof key (none)"},
		},
		{
			name: "keyreg with only a selection key is not offline",
			txn: types.Transaction{
				Type:            types.KeyRegistrationTx,
				Header:          types.Header{Sender: sender},
				KeyregTxnFields: types.KeyregTxnFields{SelectionPK: types.VRFPK{2}},
			},
			want: []string{"keyreg: go online", "vote key (none)", "!! a key is missing"},
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
			want: []string{"!! asset 5: reconfigure", "manager=" + other.String() + " reserve=(none)"},
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

func TestPluginReviewMatchesTheSignersRulesWhereTheyOverlap(t *testing.T) {
	sender, other := reviewTestAddress(1), reviewTestAddress(2)
	lines := func(txn types.Transaction) string { return strings.Join(pluginReviewLines(txn), "\n") }

	// The sender named as the asset sender is not a clawback.
	own := lines(types.Transaction{
		Type:   types.AssetTransferTx,
		Header: types.Header{Sender: sender},
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset: 7, AssetAmount: 1, AssetReceiver: other, AssetSender: sender,
		},
	})
	if strings.Contains(own, "CLAWBACK") {
		t.Errorf("a transfer whose asset sender is the sender is marked a clawback:\n%s", own)
	}

	create := lines(types.Transaction{
		Type:   types.AssetConfigTx,
		Header: types.Header{Sender: sender},
		AssetConfigTxnFields: types.AssetConfigTxnFields{AssetParams: types.AssetParams{
			Total: 10, Decimals: 2, DefaultFrozen: true, AssetName: "USD Coin", UnitName: "USDC\x1b[2J", URL: "https://x",
		}},
	})
	for _, want := range []string{"default frozen true", `name "USD Coin"`, `unit "USDC\\x1b[2J"`, `url "https://x"`} {
		if !strings.Contains(create, want) {
			t.Errorf("asset create review missing %q:\n%s", want, create)
		}
	}

	update := lines(types.Transaction{
		Type:   types.ApplicationCallTx,
		Header: types.Header{Sender: sender},
		ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{
			ApplicationID: 9, OnCompletion: types.UpdateApplicationOC, ApprovalProgram: []byte{6}, ClearStateProgram: []byte{6},
		}},
	})
	if strings.Contains(update, "state:") {
		t.Errorf("an app update shows state sizes, which only a create sets:\n%s", update)
	}
	created := lines(types.Transaction{
		Type:   types.ApplicationCallTx,
		Header: types.Header{Sender: sender},
		ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{
			ApprovalProgram: []byte{6}, ClearStateProgram: []byte{6},
			BoxReferences: []types.BoxReference{{Name: []byte("b")}, {ForeignAppIdx: 3, Name: []byte("c")}},
		}},
	})
	for _, want := range []string{"state: global", `box[0]: the app being created, name "b"`, "box[1]: ?app[2] (no such entry)"} {
		if !strings.Contains(created, want) {
			t.Errorf("app create review missing %q:\n%s", want, created)
		}
	}
}
