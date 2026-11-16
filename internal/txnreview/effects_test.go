// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func effectTxn(kind types.TxType, edit func(*types.Transaction)) types.Transaction {
	txn := types.Transaction{Type: kind}
	txn.Sender = detailsAddr(1)
	txn.Fee = 1000
	if edit != nil {
		edit(&txn)
	}
	return txn
}

// Each transaction type yields the effects its fields describe, with the
// severity its findings give them.
func TestEffectsByTransactionType(t *testing.T) {
	sender, other, third := detailsAddr(1).String(), detailsAddr(2).String(), detailsAddr(3).String()
	type want struct {
		kind     EffectKind
		from, to string
		text     string
		severity Severity
	}
	tests := []struct {
		name string
		txn  types.Transaction
		want []want
	}{
		{"payment", effectTxn(types.PaymentTx, func(x *types.Transaction) {
			x.Receiver, x.Amount = detailsAddr(2), 5_000_000
		}), []want{{EffectTransfer, sender, other, "5.000000 ALGO", SeverityNormal}}},
		{"payment to itself", effectTxn(types.PaymentTx, func(x *types.Transaction) {
			x.Receiver = x.Sender
		}), []want{{EffectSelfSend, sender, "", "0.000000 ALGO to itself", SeverityNormal}}},
		{"payment to the zero address", effectTxn(types.PaymentTx, func(x *types.Transaction) {
			x.Amount = 1
		}), []want{{EffectTransfer, sender, types.Address{}.String(), "0.000001 ALGO", SeverityCaution}}},
		{"close with no amount", effectTxn(types.PaymentTx, func(x *types.Transaction) {
			x.Receiver, x.CloseRemainderTo = detailsAddr(2), detailsAddr(3)
		}), []want{{EffectClose, sender, third, "CLOSE: all remaining ALGO", SeverityDanger}}},
		{"payment and close and rekey", effectTxn(types.PaymentTx, func(x *types.Transaction) {
			x.Receiver, x.Amount, x.CloseRemainderTo, x.RekeyTo = detailsAddr(2), 7, detailsAddr(3), detailsAddr(2)
		}), []want{
			{EffectTransfer, sender, other, "0.000007 ALGO", SeverityNormal},
			{EffectClose, sender, third, "CLOSE: all remaining ALGO", SeverityDanger},
			{EffectRekey, sender, other, "REKEY: control moves", SeverityDanger},
		}},
		{"pure rekey", effectTxn(types.PaymentTx, func(x *types.Transaction) {
			x.Receiver, x.RekeyTo = x.Sender, detailsAddr(2)
		}), []want{{EffectRekey, sender, other, "REKEY: control moves", SeverityDanger}}},
		{"rekey to its own address", effectTxn(types.PaymentTx, func(x *types.Transaction) {
			x.Receiver, x.RekeyTo = x.Sender, x.Sender
		}), []want{{EffectRekey, sender, sender, "rekey to its own address", SeverityDanger}}},
		{"asset transfer", effectTxn(types.AssetTransferTx, func(x *types.Transaction) {
			x.XferAsset, x.AssetAmount, x.AssetReceiver = 9, 150, detailsAddr(2)
		}), []want{{EffectTransfer, sender, other, "150 base units of asset #9", SeverityNormal}}},
		{"opt in", effectTxn(types.AssetTransferTx, func(x *types.Transaction) {
			x.XferAsset, x.AssetReceiver = 9, x.Sender
		}), []want{{EffectOptIn, sender, "", "opt in to asset #9", SeverityNormal}}},
		{"asset close out", effectTxn(types.AssetTransferTx, func(x *types.Transaction) {
			x.XferAsset, x.AssetReceiver, x.AssetCloseTo = 9, detailsAddr(2), detailsAddr(3)
		}), []want{{EffectClose, sender, third, "CLOSE: all remaining asset #9", SeverityCaution}}},
		{"clawback", effectTxn(types.AssetTransferTx, func(x *types.Transaction) {
			x.XferAsset, x.AssetAmount, x.AssetSender, x.AssetReceiver = 9, 5, detailsAddr(2), detailsAddr(3)
		}), []want{{EffectClawback, other, third, "CLAWBACK 5 base units of asset #9", SeverityCaution}}},
		{"freeze", effectTxn(types.AssetFreezeTx, func(x *types.Transaction) {
			x.FreezeAsset, x.FreezeAccount, x.AssetFrozen = 9, detailsAddr(2), true
		}), []want{{EffectFreeze, sender, other, "freeze asset #9", SeverityCaution}}},
		{"app call", effectTxn(types.ApplicationCallTx, func(x *types.Transaction) {
			x.ApplicationID = 44
		}), []want{{EffectAppCall, sender, "", "call", SeverityNormal}}},
		{"app update", effectTxn(types.ApplicationCallTx, func(x *types.Transaction) {
			x.ApplicationID, x.OnCompletion = 44, types.UpdateApplicationOC
		}), []want{{EffectAppCall, sender, "", "UPDATE program", SeverityCaution}}},
		{"app create", effectTxn(types.ApplicationCallTx, nil),
			[]want{{EffectAppCall, sender, "", "create app", SeverityNormal}}},
		{"go offline", effectTxn(types.KeyRegistrationTx, nil),
			[]want{{EffectKeyReg, sender, "", "go offline", SeverityNormal}}},
		{"nonparticipating", effectTxn(types.KeyRegistrationTx, func(x *types.Transaction) {
			x.Nonparticipation = true
		}), []want{{EffectKeyReg, sender, "", "NONPARTICIPATING, for good", SeverityDanger}}},
		{"go online", effectTxn(types.KeyRegistrationTx, func(x *types.Transaction) {
			x.VotePK[0], x.SelectionPK[0] = 1, 1
		}), []want{{EffectKeyReg, sender, "", "go online", SeverityNormal}}},
		{"asset create", effectTxn(types.AssetConfigTx, func(x *types.Transaction) {
			x.AssetParams.Total, x.AssetParams.UnitName = 10, "GOLD"
		}), []want{{EffectAssetCreate, sender, "", "create asset GOLD", SeverityNormal}}},
		{"asset destroy", effectTxn(types.AssetConfigTx, func(x *types.Transaction) {
			x.ConfigAsset = 9
		}), []want{{EffectAssetDestroy, sender, "", "DESTROY asset #9", SeverityDanger}}},
		{"asset reconfigure", effectTxn(types.AssetConfigTx, func(x *types.Transaction) {
			x.ConfigAsset, x.AssetParams.Manager = 9, detailsAddr(2)
		}), []want{{EffectAssetConfig, sender, "", "reconfigure asset #9", SeverityCaution}}},
		{"unknown type", effectTxn(types.TxType("hb"), nil), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Detail(tc.txn, View{})
			d.Mark(Findings(tc.txn, FindingContext{}))
			if len(d.Effects) != len(tc.want) {
				t.Fatalf("effects = %+v, want %d", d.Effects, len(tc.want))
			}
			for i, w := range tc.want {
				got := d.Effects[i]
				if got.Kind != w.kind || got.From != w.from || got.To != w.to || got.Text != w.text || got.Severity != w.severity {
					t.Errorf("effect %d = %+v, want %+v", i, got, w)
				}
			}
		})
	}
}

// A clawback names the account that acts, and an app call its app.
func TestEffectsNameAuthorityAndApp(t *testing.T) {
	clawback := effectTxn(types.AssetTransferTx, func(x *types.Transaction) {
		x.XferAsset, x.AssetSender, x.AssetReceiver = 9, detailsAddr(2), detailsAddr(3)
	})
	if got := Detail(clawback, View{}).Effects[0].Authority; got != detailsAddr(1).String() {
		t.Errorf("clawback authority = %q", got)
	}
	call := effectTxn(types.ApplicationCallTx, func(x *types.Transaction) { x.ApplicationID = 44 })
	if got := Detail(call, View{}).Effects[0]; got.App != 44 || got.NewApp {
		t.Errorf("app call = %+v", got)
	}
	create := effectTxn(types.ApplicationCallTx, nil)
	if got := Detail(create, View{}).Effects[0]; got.App != 0 || !got.NewApp {
		t.Errorf("app create = %+v", got)
	}
}

// A rekey the signer issued itself has no finding, so its effect is not
// marked: severity follows the findings, not the kind.
func TestEffectSeverityFollowsFindings(t *testing.T) {
	txn := effectTxn(types.PaymentTx, func(x *types.Transaction) {
		x.Receiver, x.RekeyTo = x.Sender, detailsAddr(2)
	})
	d := Detail(txn, View{})
	d.Mark(Findings(txn, FindingContext{ProtocolRekeyTargets: map[string]bool{detailsAddr(2).String(): true}}))
	if got := d.Effects[0]; got.Kind != EffectRekey || got.Severity != SeverityNormal {
		t.Fatalf("protocol rekey = %+v", got)
	}
	d.Mark(Findings(txn, FindingContext{}))
	if got := d.Effects[0].Severity; got != SeverityDanger {
		t.Fatalf("rekey severity = %q", got)
	}
}

// Every finding that speaks of a transaction field marks an effect, so no
// finding is missing from the picture.
func TestEveryFieldFindingMarksAnEffect(t *testing.T) {
	txns := []types.Transaction{
		effectTxn(types.PaymentTx, func(x *types.Transaction) {
			x.Amount, x.CloseRemainderTo, x.RekeyTo = 1, detailsAddr(3), detailsAddr(2)
		}),
		effectTxn(types.AssetTransferTx, func(x *types.Transaction) {
			x.XferAsset, x.AssetSender, x.AssetReceiver, x.AssetCloseTo = 9, detailsAddr(2), detailsAddr(3), detailsAddr(3)
		}),
		effectTxn(types.AssetFreezeTx, func(x *types.Transaction) { x.FreezeAsset = 9 }),
		effectTxn(types.ApplicationCallTx, func(x *types.Transaction) { x.ApplicationID, x.OnCompletion = 4, types.DeleteApplicationOC }),
		effectTxn(types.ApplicationCallTx, func(x *types.Transaction) { x.ApplicationID, x.OnCompletion = 4, types.ClearStateOC }),
		effectTxn(types.AssetConfigTx, func(x *types.Transaction) { x.ConfigAsset = 9 }),
		effectTxn(types.KeyRegistrationTx, func(x *types.Transaction) { x.Nonparticipation = true }),
		effectTxn(types.KeyRegistrationTx, func(x *types.Transaction) { x.VotePK[0] = 1 }),
	}
	for i, txn := range txns {
		findings := Findings(txn, FindingContext{})
		d := Detail(txn, View{})
		d.Mark(findings)
		for _, finding := range findings {
			if finding.Field == "Fee" {
				continue
			}
			marked := false
			for _, effect := range d.Effects {
				if effect.field == finding.Field && effect.Severity != SeverityNormal {
					marked = true
				}
			}
			if !marked {
				t.Errorf("transaction %d: finding %s marks no effect: %+v", i, finding.Field, d.Effects)
			}
		}
	}
}
