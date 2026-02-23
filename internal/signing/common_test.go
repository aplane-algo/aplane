// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package signing

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestCleanSubmitError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "logic rejection with struct dump",
			err:  fmt.Errorf(`HTTP 400: {"data":{"eval-states":[{}],"group-index":0,"pc":17},"message":"transaction {_struct:{} Sig:[0 0 0] Lsig:{Logic:[12 38 1]} Args:[[186 0 153]]} Txn:{Type:pay}} invalid : transaction 6XDV3KPBGTZKUWMY7B6AUXUJZKMPQORACVJFF2JU5AR2XWKX6MKQ: rejected by logic err=cannot load arg[1] of 1. Details: pc=17"}`),
			want: "transaction 6XDV3KPBGTZKUWMY7B6AUXUJZKMPQORACVJFF2JU5AR2XWKX6MKQ: rejected by logic err=cannot load arg[1] of 1. Details: pc=17",
		},
		{
			name: "overspend error",
			err:  fmt.Errorf(`HTTP 400: {"message":"transaction {_struct:{} ...} invalid : transaction TXID: overspend"}`),
			want: "transaction TXID: overspend",
		},
		{
			name: "unrelated error passes through",
			err:  fmt.Errorf("connection refused"),
			want: "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanSubmitError(tt.err)
			if got.Error() != tt.want {
				t.Errorf("cleanSubmitError() = %q, want %q", got.Error(), tt.want)
			}
		})
	}
}

// TestAdjustLSigFeesForDummies verifies fee splitting logic
func TestAdjustLSigFeesForDummies(t *testing.T) {
	const minFee = 1000 // Standard Algorand minimum fee

	tests := []struct {
		name         string
		numTxns      int
		lsigIndices  []int
		dummyCount   int
		minFee       uint64
		incentiveFee uint64
		wantFees     []uint64 // Expected fees for LSig transactions
		wantErr      bool
	}{
		{
			name:        "single lsig with 3 dummies",
			numTxns:     4, // 1 LSig + 3 dummies
			lsigIndices: []int{0},
			dummyCount:  3,
			minFee:      minFee,
			wantFees:    []uint64{3000}, // 3 dummies × 1000 = 3000
		},
		{
			name:        "two lsigs with 5 dummies",
			numTxns:     7, // 2 LSigs + 5 dummies
			lsigIndices: []int{0, 1},
			dummyCount:  5,
			minFee:      minFee,
			wantFees:    []uint64{2500, 2500}, // 5000 ÷ 2 = 2500 each
		},
		{
			name:        "uneven split with remainder",
			numTxns:     6, // 3 LSigs + 3 dummies
			lsigIndices: []int{0, 2, 4},
			dummyCount:  5,
			minFee:      minFee,
			wantFees:    []uint64{1668, 1666, 1666}, // 5000 ÷ 3 = 1666 + remainder 2 to first
		},
		{
			name:         "with incentive fee",
			numTxns:      4,
			lsigIndices:  []int{0},
			dummyCount:   3,
			minFee:       minFee,
			incentiveFee: 2000000,           // 2 ALGO
			wantFees:     []uint64{2003000}, // 3000 (dummy fees) + 2000000 (incentive)
		},
		{
			name:         "multiple lsigs with incentive",
			numTxns:      7,
			lsigIndices:  []int{0, 1},
			dummyCount:   5,
			minFee:       minFee,
			incentiveFee: 1000000,                 // 1 ALGO
			wantFees:     []uint64{1002500, 2500}, // First gets 2500 + 1000000, second gets 2500
		},
		{
			name:        "zero dummies",
			numTxns:     1,
			lsigIndices: []int{0},
			dummyCount:  0,
			minFee:      minFee,
			wantFees:    []uint64{0}, // No dummy fees to add
		},
		{
			name:        "non-sequential indices",
			numTxns:     8,
			lsigIndices: []int{1, 3, 7},
			dummyCount:  6,
			minFee:      minFee,
			wantFees:    []uint64{2000, 2000, 2000}, // 6000 ÷ 3 = 2000 each
		},
		{
			name:        "invalid index (negative)",
			numTxns:     4,
			lsigIndices: []int{-1},
			dummyCount:  3,
			minFee:      minFee,
			wantErr:     true,
		},
		{
			name:        "invalid index (out of bounds)",
			numTxns:     4,
			lsigIndices: []int{5},
			dummyCount:  3,
			minFee:      minFee,
			wantErr:     true,
		},
		{
			name:        "empty lsig indices",
			numTxns:     4,
			lsigIndices: []int{},
			dummyCount:  3,
			minFee:      minFee,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create transactions with initial fees of 1000 (standard min)
			txns := make([]types.Transaction, tt.numTxns)
			for i := range txns {
				txns[i].Fee = types.MicroAlgos(minFee)
			}

			// Call the function
			err := AdjustLSigFeesForDummies(txns, tt.lsigIndices, tt.dummyCount, tt.minFee, tt.incentiveFee)

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Fatalf("AdjustLSigFeesForDummies() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return // Expected error, test passed
			}

			// Verify fees on LSig transactions
			if len(tt.wantFees) != len(tt.lsigIndices) {
				t.Fatalf("Test configuration error: wantFees length (%d) != lsigIndices length (%d)",
					len(tt.wantFees), len(tt.lsigIndices))
			}

			for i, idx := range tt.lsigIndices {
				gotFee := uint64(txns[idx].Fee)
				wantFee := tt.wantFees[i] + minFee // Add initial fee
				if gotFee != wantFee {
					t.Errorf("LSig transaction %d (index %d): fee = %d, want %d",
						i, idx, gotFee, wantFee)
				}
			}

			// Verify total fees equal expected
			totalLSigFees := uint64(0)
			for _, idx := range tt.lsigIndices {
				totalLSigFees += uint64(txns[idx].Fee)
			}

			expectedTotal := uint64(len(tt.lsigIndices))*minFee + // Initial fees
				uint64(tt.dummyCount)*tt.minFee + // Dummy fees
				tt.incentiveFee // Incentive fee

			if totalLSigFees != expectedTotal {
				t.Errorf("Total LSig fees = %d, want %d (initial: %d, dummy fees: %d, incentive: %d)",
					totalLSigFees, expectedTotal,
					len(tt.lsigIndices)*minFee, tt.dummyCount*minFee, tt.incentiveFee)
			}
		})
	}
}

// TestAssignGroupID verifies group ID computation and assignment
func TestAssignGroupID(t *testing.T) {
	// Create sample transactions
	txn1 := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: types.Address{1, 2, 3},
			Fee:    types.MicroAlgos(1000),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{4, 5, 6},
			Amount:   types.MicroAlgos(1000000),
		},
	}

	txn2 := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: types.Address{7, 8, 9},
			Fee:    types.MicroAlgos(1000),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{10, 11, 12},
			Amount:   types.MicroAlgos(2000000),
		},
	}

	txns := []types.Transaction{txn1, txn2}

	// Assign group ID
	gid, err := AssignGroupID(txns)
	if err != nil {
		t.Fatalf("AssignGroupID failed: %v", err)
	}

	// Verify group ID is non-zero
	var zeroGID types.Digest
	if gid == zeroGID {
		t.Error("Group ID should not be zero")
	}

	// Verify all transactions have the same group ID
	for i, txn := range txns {
		if txn.Group != gid {
			t.Errorf("Transaction %d has group ID %v, want %v", i, txn.Group, gid)
		}
	}

	// Verify determinism: same transactions should produce same group ID
	txns2 := []types.Transaction{txn1, txn2}
	gid2, err := AssignGroupID(txns2)
	if err != nil {
		t.Fatalf("Second AssignGroupID failed: %v", err)
	}
	if gid != gid2 {
		t.Error("Same transactions should produce same group ID")
	}

	// Verify different transactions produce different group ID
	txn3 := txn2
	txn3.Amount = types.MicroAlgos(3000000) // Different amount
	txns3 := []types.Transaction{txn1, txn3}
	gid3, err := AssignGroupID(txns3)
	if err != nil {
		t.Fatalf("Third AssignGroupID failed: %v", err)
	}
	if gid == gid3 {
		t.Error("Different transactions should produce different group IDs")
	}
}
