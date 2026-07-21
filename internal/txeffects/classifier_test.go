// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txeffects

import (
	"reflect"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestBounded1ManifestValidAndDefensive(t *testing.T) {
	manifest := Bounded1Manifest()
	if err := manifest.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	manifest.SpendEffects[0] = SpendEffect("appl")
	manifest.Predicates[0].Field = FieldAssetSender
	manifest.KnownDeniedTypes[0] = types.PaymentTx

	fresh := Bounded1Manifest()
	if fresh.SpendEffects[0] != SpendEffectPay {
		t.Fatal("spend effects share mutable backing storage")
	}
	if fresh.Predicates[0].Field != FieldRekeyTo {
		t.Fatal("predicates share mutable backing storage")
	}
	if fresh.KnownDeniedTypes[0] != "" {
		t.Fatal("known denied types share mutable backing storage")
	}
}

func TestManifestRejectsUnknownContractVocabulary(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ContractManifest)
	}{
		{name: "spend effect", mutate: func(m *ContractManifest) { m.SpendEffects[0] = "future_spend" }},
		{name: "danger effect", mutate: func(m *ContractManifest) { m.Predicates[0].Effect = "future_effect" }},
		{name: "transaction field", mutate: func(m *ContractManifest) { m.Predicates[0].Field = "FutureField" }},
		{name: "predicate test", mutate: func(m *ContractManifest) { m.Predicates[0].Test = "future_test" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := Bounded1Manifest()
			test.mutate(&manifest)
			if err := manifest.Validate(); err == nil {
				t.Fatal("Validate() accepted unknown contract vocabulary")
			}
		})
	}
}

func TestClassifierInternalMappingsPanicOnUnknownVocabulary(t *testing.T) {
	assertPanics(t, func() { _ = mustEffectBit("future_effect") })
	assertPanics(t, func() {
		_ = mustMatch(types.Transaction{}, FieldPredicate{
			Effect: EffectRekey, Field: "FutureField", Test: TestAddressNonZero,
		})
	})
	assertPanics(t, func() {
		_ = mustMatch(types.Transaction{}, FieldPredicate{
			Effect: EffectRekey, Field: FieldRekeyTo, Test: "future_test",
		})
	})
}

func assertPanics(t *testing.T, run func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("operation did not panic")
		}
	}()
	run()
}

func TestInspectClassifiesEveryEffectCombination(t *testing.T) {
	sender := types.Address{1}
	target := types.Address{2}
	wantOrder := []EffectKind{EffectRekey, EffectClose, EffectAssetClose, EffectClawback}

	for mask := 1; mask < 1<<len(wantOrder); mask++ {
		txn := types.Transaction{
			Type:             types.PaymentTx,
			Header:           types.Header{Sender: sender},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: sender},
		}
		var want []EffectKind
		if mask&1 != 0 {
			txn.RekeyTo = target
			want = append(want, EffectRekey)
		}
		if mask&2 != 0 {
			txn.CloseRemainderTo = target
			want = append(want, EffectClose)
		}
		if mask&4 != 0 {
			txn.AssetCloseTo = target
			want = append(want, EffectAssetClose)
		}
		if mask&8 != 0 {
			txn.AssetSender = target
			want = append(want, EffectClawback)
		}

		got := Classify(txn)
		if !reflect.DeepEqual(got.Facts.Effects(), want) {
			t.Fatalf("mask %04b effects = %v, want %v", mask, got.Facts.Effects(), want)
		}
		wantShape := ShapeDeniedEffect
		if mask == 1 {
			wantShape = ShapePureRekey
		} else if mask&1 != 0 {
			wantShape = ShapeHybrid
		}
		if got.Shape != wantShape {
			t.Fatalf("mask %04b shape = %q, want %q", mask, got.Shape, wantShape)
		}
	}
}

func TestClassifyBounded1Shapes(t *testing.T) {
	sender := types.Address{1}
	target := types.Address{2}
	other := types.Address{3}
	pureRekey := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender, RekeyTo: target, Fee: 10_000},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: sender},
	}

	tests := []struct {
		name   string
		txn    types.Transaction
		want   Shape
		effect SpendEffect
	}{
		{name: "payment spend", txn: types.Transaction{Type: types.PaymentTx}, want: ShapePureSpend, effect: SpendEffectPay},
		{name: "asset spend", txn: types.Transaction{Type: types.AssetTransferTx, AssetTransferTxnFields: types.AssetTransferTxnFields{AssetAmount: 1}}, want: ShapePureSpend, effect: SpendEffectAxfer},
		{name: "asset opt-in", txn: types.Transaction{Type: types.AssetTransferTx, Header: types.Header{Sender: sender}, AssetTransferTxnFields: types.AssetTransferTxnFields{AssetReceiver: sender}}, want: ShapePureSpend, effect: SpendEffectAssetOptIn},
		{name: "pure rekey", txn: pureRekey, want: ShapePureRekey},
		{name: "rekey payment amount", txn: withAmount(pureRekey, 1), want: ShapeHybrid},
		{name: "rekey payment receiver", txn: withReceiver(pureRekey, other), want: ShapeHybrid},
		{name: "rekey wrong type", txn: withType(pureRekey, types.AssetTransferTx), want: ShapeHybrid},
		{name: "close only", txn: types.Transaction{Type: types.PaymentTx, PaymentTxnFields: types.PaymentTxnFields{CloseRemainderTo: target}}, want: ShapeDeniedEffect},
		{name: "unknown type", txn: types.Transaction{}, want: ShapeDeniedType},
		{name: "application type", txn: types.Transaction{Type: types.ApplicationCallTx}, want: ShapeDeniedType},
		{name: "unknown type with rekey", txn: types.Transaction{Header: types.Header{Sender: sender, RekeyTo: target}, PaymentTxnFields: types.PaymentTxnFields{Receiver: sender}}, want: ShapeHybrid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.txn)
			if got.Shape != tt.want {
				t.Fatalf("Classify().Shape = %q, want %q", got.Shape, tt.want)
			}
			if got.SpendEffect != tt.effect {
				t.Fatalf("Classify().SpendEffect = %q, want %q", got.SpendEffect, tt.effect)
			}
			if got.Facts.TransactionType != tt.txn.Type || got.Facts.Fee != tt.txn.Fee {
				t.Fatalf("Classify().Facts = %+v, want type %q fee %d", got.Facts, tt.txn.Type, tt.txn.Fee)
			}
		})
	}
}

func TestSameSenderAssetSenderRemainsConservativeFact(t *testing.T) {
	sender := types.Address{1}
	txn := types.Transaction{
		Type:                   types.AssetTransferTx,
		Header:                 types.Header{Sender: sender},
		AssetTransferTxnFields: types.AssetTransferTxnFields{AssetSender: sender},
	}
	got := Classify(txn)
	if !got.Facts.Has(EffectClawback) {
		t.Fatal("same-sender AssetSender was not classified as a bounded danger effect")
	}
	if got.Shape != ShapeDeniedEffect {
		t.Fatalf("shape = %q, want %q", got.Shape, ShapeDeniedEffect)
	}
}

func withAmount(txn types.Transaction, amount types.MicroAlgos) types.Transaction {
	txn.Amount = amount
	return txn
}

func withReceiver(txn types.Transaction, receiver types.Address) types.Transaction {
	txn.Receiver = receiver
	return txn
}

func withType(txn types.Transaction, txType types.TxType) types.Transaction {
	txn.Type = txType
	return txn
}
