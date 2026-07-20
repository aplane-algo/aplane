// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

func TestFalconBoundedReplacementNarrowsGovernedFGCorpus(t *testing.T) {
	sender := types.Address{1}
	allowed := types.Address{2}
	foreign := types.Address{3}
	rekeyTarget := types.Address{4}
	basePayment := func() types.Transaction {
		return types.Transaction{
			Type: types.PaymentTx, Header: types.Header{Sender: sender, Fee: 1_000},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: allowed, Amount: 10},
		}
	}
	baseAsset := func() types.Transaction {
		return types.Transaction{
			Type: types.AssetTransferTx, Header: types.Header{Sender: sender, Fee: 1_000},
			AssetTransferTxnFields: types.AssetTransferTxnFields{AssetReceiver: allowed, AssetAmount: 10, XferAsset: 7},
		}
	}

	tests := []struct {
		name       string
		build      func() types.Transaction
		adminProof bool
		legacy     bool
		bounded    bool
	}{
		{name: "allowed payment", build: basePayment, legacy: true, bounded: true},
		{name: "foreign payment", build: func() types.Transaction { txn := basePayment(); txn.Receiver = foreign; return txn }},
		{name: "allowed asset transfer", build: baseAsset, legacy: true, bounded: true},
		{name: "foreign asset transfer", build: func() types.Transaction { txn := baseAsset(); txn.AssetReceiver = foreign; return txn }},
		{name: "self asset opt-in", build: func() types.Transaction {
			txn := baseAsset()
			txn.AssetReceiver = sender
			txn.AssetAmount = 0
			return txn
		}, legacy: true, bounded: true},
		{name: "payment close to allowlist", build: func() types.Transaction { txn := basePayment(); txn.CloseRemainderTo = allowed; return txn }, legacy: true},
		{name: "asset close to allowlist", build: func() types.Transaction { txn := baseAsset(); txn.AssetCloseTo = allowed; return txn }, legacy: true},
		{name: "asset clawback", build: func() types.Transaction { txn := baseAsset(); txn.AssetSender = foreign; return txn }, legacy: true},
		{name: "unsupported keyreg", build: func() types.Transaction { txn := basePayment(); txn.Type = types.KeyRegistrationTx; return txn }, legacy: true},
		{name: "unsupported app call", build: func() types.Transaction { txn := basePayment(); txn.Type = types.ApplicationCallTx; return txn }, legacy: true},
		{name: "fee above ceiling", build: func() types.Transaction {
			txn := basePayment()
			txn.Fee = types.MicroAlgos(composeddsa.BoundedMaxFeeV1 + 1)
			return txn
		}, legacy: true},
		{name: "pure rekey without admin proof", build: func() types.Transaction {
			txn := basePayment()
			txn.Amount = 0
			txn.Receiver = sender
			txn.RekeyTo = rekeyTarget
			return txn
		}},
		{name: "pure rekey with admin proof", build: func() types.Transaction {
			txn := basePayment()
			txn.Amount = 0
			txn.Receiver = sender
			txn.RekeyTo = rekeyTarget
			return txn
		}, adminProof: true, legacy: true, bounded: true},
		{name: "rekey plus ignored asset close", build: func() types.Transaction {
			txn := basePayment()
			txn.Amount = 0
			txn.Receiver = sender
			txn.RekeyTo = rekeyTarget
			txn.AssetCloseTo = foreign
			return txn
		}, adminProof: true, legacy: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			txn := test.build()
			if got := legacyGovernedFGAllows(txn, allowed, test.adminProof); got != test.legacy {
				t.Fatalf("legacy governed FG acceptance = %v, want %v", got, test.legacy)
			}
			if got := boundedFixedAllowlistAllows(txn, allowed, test.adminProof); got != test.bounded {
				t.Fatalf("bounded fixed allowlist acceptance = %v, want %v", got, test.bounded)
			}
			if test.bounded && !test.legacy {
				t.Fatal("replacement widened the legacy acceptance set")
			}
		})
	}
}

func TestFalconBoundedReplacementOperationalCost(t *testing.T) {
	const (
		legacyFG30Bytecode = 5_013
		legacyFG30Signed   = 7_573
		bounded30Bytecode  = 5_279
		bounded30Signed    = 7_839
	)
	if delta := bounded30Bytecode - legacyFG30Bytecode; delta != 266 {
		t.Fatalf("bytecode delta = %d, want 266", delta)
	}
	if delta := bounded30Signed - legacyFG30Signed; delta != 266 {
		t.Fatalf("post-signing delta = %d, want 266", delta)
	}
	if legacyGroup, boundedGroup := (legacyFG30Signed+999)/1000, (bounded30Signed+999)/1000; legacyGroup != 8 || boundedGroup != 8 {
		t.Fatalf("required groups = legacy %d, bounded %d; want 8/8", legacyGroup, boundedGroup)
	}
}

// legacyGovernedFGAllows snapshots the removed FG provider's on-chain policy.
// It is retained only as an adversarial differential oracle.
func legacyGovernedFGAllows(txn types.Transaction, allowed types.Address, adminProof bool) bool {
	if !txn.RekeyTo.IsZero() {
		return adminProof && txn.Type == types.PaymentTx && txn.Amount == 0 && txn.Receiver == txn.Sender && txn.CloseRemainderTo.IsZero()
	}
	switch txn.Type {
	case types.PaymentTx:
		return (txn.Receiver == txn.Sender || txn.Receiver == allowed) &&
			(txn.CloseRemainderTo.IsZero() || txn.CloseRemainderTo == txn.Sender || txn.CloseRemainderTo == allowed)
	case types.AssetTransferTx:
		return (txn.AssetReceiver == txn.Sender || txn.AssetReceiver == allowed) &&
			(txn.AssetCloseTo.IsZero() || txn.AssetCloseTo == txn.Sender || txn.AssetCloseTo == allowed)
	default:
		return true
	}
}

func boundedFixedAllowlistAllows(txn types.Transaction, allowed types.Address, adminProof bool) bool {
	if uint64(txn.Fee) > composeddsa.BoundedMaxFeeV1 {
		return false
	}
	switch txeffects.Classify(txn).Shape {
	case txeffects.ShapePureRekey:
		return adminProof
	case txeffects.ShapePureSpend:
		switch txn.Type {
		case types.PaymentTx:
			return txn.Receiver == txn.Sender || txn.Receiver == allowed
		case types.AssetTransferTx:
			return txn.AssetReceiver == txn.Sender || txn.AssetReceiver == allowed
		}
	}
	return false
}
