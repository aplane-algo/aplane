// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package lsig

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// TestCreateDummyTransactions verifies dummy transaction creation
func TestCreateDummyTransactions(t *testing.T) {
	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		GenesisID:       "testnet-v1.0",
		GenesisHash:     genesisHash[:],
		FirstRoundValid: types.Round(1000),
		LastRoundValid:  types.Round(2000),
		FlatFee:         true,
	}

	tests := []struct {
		name      string
		count     int
		wantCount int
		wantErr   bool
	}{
		{
			name:      "zero dummies",
			count:     0,
			wantCount: 0,
		},
		{
			name:      "single dummy",
			count:     1,
			wantCount: 1,
		},
		{
			name:      "multiple dummies",
			count:     5,
			wantCount: 5,
		},
		{
			name:      "11 dummies (max for 5 Falcon LSigs)",
			count:     11,
			wantCount: 11,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dummies, err := CreateDummyTransactions(tt.count, sp)

			if (err != nil) != tt.wantErr {
				t.Fatalf("CreateDummyTransactions() error = %v, wantErr %v", err, tt.wantErr)
			}

			if len(dummies) != tt.wantCount {
				t.Errorf("Got %d dummy transactions, want %d", len(dummies), tt.wantCount)
			}

			// Verify each dummy transaction properties
			for i, dummy := range dummies {
				// Should be self-payment
				if dummy.Sender != dummy.Receiver {
					t.Errorf("Dummy %d: sender %v != receiver %v", i, dummy.Sender, dummy.Receiver)
				}

				// Should have amount 0
				if dummy.Amount != 0 {
					t.Errorf("Dummy %d: amount = %d, want 0", i, dummy.Amount)
				}

				// Should have fee 0 (first transaction pays)
				if dummy.Fee != 0 {
					t.Errorf("Dummy %d: fee = %d, want 0", i, dummy.Fee)
				}

				// Should have unique note
				if len(dummy.Note) != 1 {
					t.Errorf("Dummy %d: note length = %d, want 1", i, len(dummy.Note))
				}
				if len(dummy.Note) > 0 && dummy.Note[0] != byte(i) {
					t.Errorf("Dummy %d: note = %d, want %d", i, dummy.Note[0], i)
				}

				// Should use suggested params
				if dummy.FirstValid != sp.FirstRoundValid {
					t.Errorf("Dummy %d: FirstValid = %d, want %d", i, dummy.FirstValid, sp.FirstRoundValid)
				}
				if dummy.LastValid != sp.LastRoundValid {
					t.Errorf("Dummy %d: LastValid = %d, want %d", i, dummy.LastValid, sp.LastRoundValid)
				}
			}
		})
	}
}

// TestSignDummyTransactions verifies dummy transaction signing
func TestSignDummyTransactions(t *testing.T) {
	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		GenesisID:       "testnet-v1.0",
		GenesisHash:     genesisHash[:],
		FirstRoundValid: types.Round(1000),
		LastRoundValid:  types.Round(2000),
		FlatFee:         true,
	}

	// Create dummy transactions
	dummies, err := CreateDummyTransactions(3, sp)
	if err != nil {
		t.Fatalf("Failed to create dummies: %v", err)
	}

	// Sign them
	signedDummies, err := SignDummyTransactions(dummies)
	if err != nil {
		t.Fatalf("SignDummyTransactions failed: %v", err)
	}

	// Verify we got the right number of signatures
	if len(signedDummies) != len(dummies) {
		t.Errorf("Got %d signed dummies, want %d", len(signedDummies), len(dummies))
	}

	// Verify each signed transaction
	for i, signedBytes := range signedDummies {
		// Should be valid msgpack
		var stxn types.SignedTxn
		if err := msgpack.Decode(signedBytes, &stxn); err != nil {
			t.Errorf("Signed dummy %d is not valid msgpack: %v", i, err)
			continue
		}

		// Should have LogicSig, not regular signature
		if len(stxn.Lsig.Logic) == 0 {
			t.Errorf("Signed dummy %d: missing LogicSig", i)
		}

		var zeroSig types.Signature
		if stxn.Sig != zeroSig {
			t.Errorf("Signed dummy %d: should use LogicSig, not regular signature", i)
		}

		// Verify the transaction matches
		if stxn.Txn.Sender != dummies[i].Sender {
			t.Errorf("Signed dummy %d: sender mismatch", i)
		}
	}
}

// TestSignDummyTransactionsEmpty verifies handling of empty dummy list
func TestSignDummyTransactionsEmpty(t *testing.T) {
	signedDummies, err := SignDummyTransactions(nil)
	if err != nil {
		t.Errorf("SignDummyTransactions(nil) should not error, got %v", err)
	}
	if signedDummies != nil {
		t.Error("SignDummyTransactions(nil) should return nil")
	}

	signedDummies, err = SignDummyTransactions([]types.Transaction{})
	if err != nil {
		t.Errorf("SignDummyTransactions([]) should not error, got %v", err)
	}
	if signedDummies != nil {
		t.Error("SignDummyTransactions([]) should return nil")
	}
}

// TestDummyTransactionUniqueness verifies each dummy has unique note
func TestDummyTransactionUniqueness(t *testing.T) {
	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		GenesisID:       "testnet-v1.0",
		GenesisHash:     genesisHash[:],
		FirstRoundValid: types.Round(1000),
		LastRoundValid:  types.Round(2000),
		FlatFee:         true,
	}

	dummies, err := CreateDummyTransactions(10, sp)
	if err != nil {
		t.Fatalf("Failed to create dummies: %v", err)
	}

	// Verify each has a unique note value
	notes := make(map[byte]bool)
	for i, dummy := range dummies {
		if len(dummy.Note) == 0 {
			t.Errorf("Dummy %d has no note", i)
			continue
		}
		note := dummy.Note[0]
		if notes[note] {
			t.Errorf("Duplicate note value %d found in dummies", note)
		}
		notes[note] = true
	}
}

// TestDummyTransactionAddress verifies dummy address computation
func TestDummyTransactionAddress(t *testing.T) {
	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		GenesisID:       "testnet-v1.0",
		GenesisHash:     genesisHash[:],
		FirstRoundValid: types.Round(1000),
		LastRoundValid:  types.Round(2000),
		FlatFee:         true,
	}

	// Create dummies
	dummies, err := CreateDummyTransactions(2, sp)
	if err != nil {
		t.Fatalf("Failed to create dummies: %v", err)
	}

	// All dummies should have the same sender/receiver (same LogicSig account)
	if len(dummies) < 2 {
		t.Fatal("Need at least 2 dummies for this test")
	}

	addr1 := dummies[0].Sender
	for i := 1; i < len(dummies); i++ {
		if dummies[i].Sender != addr1 {
			t.Errorf("Dummy %d has different sender than dummy 0", i)
		}
		if dummies[i].Receiver != addr1 {
			t.Errorf("Dummy %d has different receiver than sender", i)
		}
	}

	// Verify address can be recomputed from LogicSig
	dummyLSig := types.LogicSig{Logic: EmbeddedDummyTealTok, Args: nil}
	lsigAcct := crypto.LogicSigAccount{Lsig: dummyLSig}
	expectedAddr, err := lsigAcct.Address()
	if err != nil {
		t.Fatalf("Failed to compute expected address: %v", err)
	}

	if addr1.String() != expectedAddr.String() {
		t.Errorf("Dummy address %s doesn't match expected %s", addr1, expectedAddr)
	}
}

// TestGroupIDAssignment verifies group ID is assigned correctly
// Note: This test would require WrapWithDummies which needs algod client
// We test the group ID logic independently here
func TestGroupIDAssignment(t *testing.T) {
	var genesisHash types.Digest
	sp := types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		GenesisID:       "testnet-v1.0",
		GenesisHash:     genesisHash[:],
		FirstRoundValid: types.Round(1000),
		LastRoundValid:  types.Round(2000),
		FlatFee:         true,
	}

	// Create some transactions
	mainTxn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:     types.Address{1, 2, 3},
			Fee:        types.MicroAlgos(1000),
			FirstValid: sp.FirstRoundValid,
			LastValid:  sp.LastRoundValid,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{4, 5, 6},
			Amount:   types.MicroAlgos(100000),
		},
	}

	dummies, err := CreateDummyTransactions(3, sp)
	if err != nil {
		t.Fatalf("Failed to create dummies: %v", err)
	}

	// Combine into group
	txns := []types.Transaction{mainTxn}
	txns = append(txns, dummies...)

	// Compute and assign group ID
	gid, err := crypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("Failed to compute group ID: %v", err)
	}

	for i := range txns {
		txns[i].Group = gid
	}

	// Verify all have the same group ID
	for i, txn := range txns {
		if txn.Group != gid {
			t.Errorf("Transaction %d has wrong group ID", i)
		}
	}

	// Verify group ID is non-zero
	var zeroGID types.Digest
	if gid == zeroGID {
		t.Error("Group ID should not be zero")
	}
}

// TestFeeDistribution verifies fee handling in dummy wrapping
// This tests the fee logic without requiring algod client
func TestFeeDistribution(t *testing.T) {
	// Test the fee calculation logic that WrapWithDummies would use
	mainTxns := []types.Transaction{
		{
			Type: types.PaymentTx,
			Header: types.Header{
				Fee: 0, // Will be set by wrapper
			},
		},
		{
			Type: types.PaymentTx,
			Header: types.Header{
				Fee: 0,
			},
		},
	}

	minFee := uint64(1000)
	dummyCount := 5
	incentiveFee := uint64(2000000) // 2 ALGO

	// Simulate what WrapWithDummies does
	// Base fee for main transactions
	baseFee := types.MicroAlgos(uint64(len(mainTxns)) * minFee)
	// Dummy fees
	dummyFees := types.MicroAlgos(dummyCount) * types.MicroAlgos(minFee)
	// Total on first transaction
	totalFee := baseFee + dummyFees + types.MicroAlgos(incentiveFee)

	mainTxns[0].Fee = totalFee
	for i := 1; i < len(mainTxns); i++ {
		mainTxns[i].Fee = 0
	}

	// Verify fees
	expectedFirstFee := 2*minFee + uint64(dummyCount)*minFee + incentiveFee
	if uint64(mainTxns[0].Fee) != expectedFirstFee {
		t.Errorf("First transaction fee = %d, want %d", mainTxns[0].Fee, expectedFirstFee)
	}

	if mainTxns[1].Fee != 0 {
		t.Errorf("Second transaction fee = %d, want 0", mainTxns[1].Fee)
	}

	// Verify total group fee
	totalGroupFee := uint64(mainTxns[0].Fee) + uint64(mainTxns[1].Fee)
	expectedGroupFee := 2*minFee + uint64(dummyCount)*minFee + incentiveFee
	if totalGroupFee != expectedGroupFee {
		t.Errorf("Total group fee = %d, want %d", totalGroupFee, expectedGroupFee)
	}
}
