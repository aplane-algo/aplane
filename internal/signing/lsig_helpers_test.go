// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// TestSignDummyTransaction tests signing with the embedded dummy LogicSig
func TestSignDummyTransaction(t *testing.T) {
	// Create a simple test transaction
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:     types.Address{1, 2, 3},
			Fee:        types.MicroAlgos(1000),
			FirstValid: 1000,
			LastValid:  2000,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{4, 5, 6},
			Amount:   types.MicroAlgos(100000),
		},
	}

	stxn, err := SignDummyTransaction(txn)
	if err != nil {
		t.Fatalf("SignDummyTransaction failed: %v", err)
	}

	// Verify the signed transaction has a LogicSig
	if len(stxn.Lsig.Logic) == 0 {
		t.Error("Signed transaction should have LogicSig program")
	}

	// Verify the LogicSig uses the embedded dummy TEAL
	if string(stxn.Lsig.Logic) != string(EmbeddedDummyTealTok) {
		t.Error("LogicSig should use embedded dummy TEAL")
	}

	// Verify no args (dummy doesn't need args)
	if len(stxn.Lsig.Args) != 0 {
		t.Error("Dummy LogicSig should have no args")
	}

	// Verify the transaction is preserved
	if stxn.Txn.Sender != txn.Sender {
		t.Error("Transaction sender should be preserved")
	}
}

// TestSignWithRawKey_ValidKey tests signing with a valid Ed25519 key
func TestSignWithRawKey_ValidKey(t *testing.T) {
	// Generate a valid Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Derive address from public key
	var pk [32]byte
	copy(pk[:], pubKey)
	expectedAddr := types.Address(pk).String()

	// Create a test transaction
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:     types.Address(pk),
			Fee:        types.MicroAlgos(1000),
			FirstValid: 1000,
			LastValid:  2000,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{4, 5, 6},
			Amount:   types.MicroAlgos(100000),
		},
	}

	// Sign with address verification
	stxn, err := SignWithRawKey(txn, privKey, expectedAddr)
	if err != nil {
		t.Fatalf("SignWithRawKey failed: %v", err)
	}

	// Verify the signed transaction has a signature
	var zeroSig types.Signature
	if stxn.Sig == zeroSig {
		t.Error("Signed transaction should have non-zero signature")
	}

	// Verify no LogicSig (this is a standard Ed25519 signature)
	if len(stxn.Lsig.Logic) != 0 {
		t.Error("Ed25519 signed transaction should not have LogicSig")
	}

	// Verify the transaction is preserved
	if stxn.Txn.Sender != txn.Sender {
		t.Error("Transaction sender should be preserved")
	}
}

// TestSignWithRawKey_NoAddressVerification tests signing without address check
func TestSignWithRawKey_NoAddressVerification(t *testing.T) {
	// Generate a valid Ed25519 key pair
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:     types.Address{1, 2, 3}, // Different from key's address
			Fee:        types.MicroAlgos(1000),
			FirstValid: 1000,
			LastValid:  2000,
		},
	}

	// Sign without address verification (empty string)
	stxn, err := SignWithRawKey(txn, privKey, "")
	if err != nil {
		t.Fatalf("SignWithRawKey should succeed without address verification: %v", err)
	}

	var zeroSig types.Signature
	if stxn.Sig == zeroSig {
		t.Error("Should produce a signature")
	}
}

// TestSignWithRawKey_AddressMismatch tests error on address mismatch
func TestSignWithRawKey_AddressMismatch(t *testing.T) {
	// Generate a valid Ed25519 key pair
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:     types.Address{1, 2, 3},
			Fee:        types.MicroAlgos(1000),
			FirstValid: 1000,
			LastValid:  2000,
		},
	}

	// Try to sign with wrong expected address
	wrongAddr := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	_, err = SignWithRawKey(txn, privKey, wrongAddr)
	if err == nil {
		t.Fatal("SignWithRawKey should fail on address mismatch")
	}

	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("Error should mention mismatch: %v", err)
	}
}

// TestSignWithRawKey_InvalidKey tests error on invalid private key
func TestSignWithRawKey_InvalidKey(t *testing.T) {
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:     types.Address{1, 2, 3},
			Fee:        types.MicroAlgos(1000),
			FirstValid: 1000,
			LastValid:  2000,
		},
	}

	// Try with invalid key (too short)
	invalidKey := []byte{1, 2, 3, 4, 5}
	_, err := SignWithRawKey(txn, invalidKey, "")
	if err == nil {
		t.Fatal("SignWithRawKey should fail on invalid key")
	}
}

// TestSignDummyTransaction_PreservesTransaction tests transaction preservation
func TestSignDummyTransaction_PreservesTransaction(t *testing.T) {
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      types.Address{1, 2, 3, 4, 5},
			Fee:         types.MicroAlgos(2000),
			FirstValid:  5000,
			LastValid:   6000,
			GenesisHash: types.Digest{9, 8, 7},
			Note:        []byte("test note"),
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{6, 7, 8, 9, 10},
			Amount:   types.MicroAlgos(500000),
		},
	}

	stxn, err := SignDummyTransaction(txn)
	if err != nil {
		t.Fatalf("SignDummyTransaction failed: %v", err)
	}

	// Verify all fields are preserved
	if stxn.Txn.Sender != txn.Sender {
		t.Error("Sender not preserved")
	}
	if stxn.Txn.Fee != txn.Fee {
		t.Error("Fee not preserved")
	}
	if stxn.Txn.FirstValid != txn.FirstValid {
		t.Error("FirstValid not preserved")
	}
	if stxn.Txn.LastValid != txn.LastValid {
		t.Error("LastValid not preserved")
	}
	if stxn.Txn.Receiver != txn.Receiver {
		t.Error("Receiver not preserved")
	}
	if stxn.Txn.Amount != txn.Amount {
		t.Error("Amount not preserved")
	}
	if string(stxn.Txn.Note) != string(txn.Note) {
		t.Error("Note not preserved")
	}
}

// Note: contains() helper is defined in ed25519_test.go
