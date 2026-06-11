// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestMatchesSelfNoOpTransferAutoApproval(t *testing.T) {
	addr := types.Address{1}
	other := types.Address{2}
	base := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: addr,
			Fee:    types.MicroAlgos(SelfNoOpTransferMaxFeeMicroAlgos),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: addr,
			Amount:   0,
		},
	}

	tests := []struct {
		name string
		edit func(*types.Transaction)
		want bool
	}{
		{name: "matches", want: true},
		{name: "non payment", edit: func(txn *types.Transaction) { txn.Type = types.KeyRegistrationTx }, want: false},
		{name: "non self receiver", edit: func(txn *types.Transaction) { txn.Receiver = other }, want: false},
		{name: "amount", edit: func(txn *types.Transaction) { txn.Amount = 1 }, want: false},
		{name: "high fee", edit: func(txn *types.Transaction) { txn.Fee = types.MicroAlgos(SelfNoOpTransferMaxFeeMicroAlgos + 1) }, want: false},
		{name: "rekey", edit: func(txn *types.Transaction) { txn.RekeyTo = other }, want: false},
		{name: "close", edit: func(txn *types.Transaction) { txn.CloseRemainderTo = other }, want: false},
		{name: "group", edit: func(txn *types.Transaction) { txn.Group = types.Digest{1} }, want: false},
		{name: "note", edit: func(txn *types.Transaction) { txn.Note = []byte("probe") }, want: false},
		{name: "lease", edit: func(txn *types.Transaction) { txn.Lease = [32]byte{1} }, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			txn := base
			if tc.edit != nil {
				tc.edit(&txn)
			}
			if got := MatchesSelfNoOpTransferAutoApproval(txn); got != tc.want {
				t.Fatalf("MatchesSelfNoOpTransferAutoApproval() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMatchesSelfNoOpTransferAutoApprovalASA(t *testing.T) {
	addr := types.Address{1}
	other := types.Address{2}
	base := types.Transaction{
		Type: types.AssetTransferTx,
		Header: types.Header{
			Sender: addr,
			Fee:    types.MicroAlgos(SelfNoOpTransferMaxFeeMicroAlgos),
		},
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset:     123,
			AssetReceiver: addr,
			AssetAmount:   0,
		},
	}

	tests := []struct {
		name string
		edit func(*types.Transaction)
		want bool
	}{
		{name: "matches", want: true},
		{name: "zero asset id", edit: func(txn *types.Transaction) { txn.XferAsset = 0 }, want: false},
		{name: "non self receiver", edit: func(txn *types.Transaction) { txn.AssetReceiver = other }, want: false},
		{name: "amount", edit: func(txn *types.Transaction) { txn.AssetAmount = 1 }, want: false},
		{name: "asset sender", edit: func(txn *types.Transaction) { txn.AssetSender = other }, want: false},
		{name: "asset close", edit: func(txn *types.Transaction) { txn.AssetCloseTo = other }, want: false},
		{name: "high fee", edit: func(txn *types.Transaction) { txn.Fee = types.MicroAlgos(SelfNoOpTransferMaxFeeMicroAlgos + 1) }, want: false},
		{name: "rekey", edit: func(txn *types.Transaction) { txn.RekeyTo = other }, want: false},
		{name: "group", edit: func(txn *types.Transaction) { txn.Group = types.Digest{1} }, want: false},
		{name: "note", edit: func(txn *types.Transaction) { txn.Note = []byte("probe") }, want: false},
		{name: "lease", edit: func(txn *types.Transaction) { txn.Lease = [32]byte{1} }, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			txn := base
			if tc.edit != nil {
				tc.edit(&txn)
			}
			if got := MatchesSelfNoOpTransferAutoApproval(txn); got != tc.want {
				t.Fatalf("MatchesSelfNoOpTransferAutoApproval() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStoredConfigApplyAutoApproveSelfNoOpTransfer(t *testing.T) {
	enabled := true
	stored := &StoredConfig{StoredPolicyCore: StoredPolicyCore{AutoApproveSelfNoOpTransfer: &enabled}}

	got, err := stored.Apply(DefaultConfig())
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !got.AutoApproveSelfNoOpTransfer {
		t.Fatal("AutoApproveSelfNoOpTransfer = false, want true")
	}
}

func TestStoredConfigApplyAlwaysReviewWarnings(t *testing.T) {
	enabled := true
	stored := &StoredConfig{StoredPolicyCore: StoredPolicyCore{AlwaysReviewWarnings: &enabled}}

	got, err := stored.Apply(DefaultConfig())
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !got.AlwaysReviewWarnings {
		t.Fatal("AlwaysReviewWarnings = false, want true")
	}
}
