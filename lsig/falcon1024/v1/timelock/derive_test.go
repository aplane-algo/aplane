// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package falcontimelock

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/algorand/falcon"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

func TestDeriveLsigDeterministic(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	unlockRound := uint64(1000000)

	bytecode1, addr1, err := DeriveLsig(kp.PublicKey[:], unlockRound)
	if err != nil {
		t.Fatalf("DeriveLsig failed: %v", err)
	}

	bytecode2, addr2, err := DeriveLsig(kp.PublicKey[:], unlockRound)
	if err != nil {
		t.Fatalf("DeriveLsig (second) failed: %v", err)
	}

	if addr1 != addr2 {
		t.Fatalf("address mismatch: %s vs %s", addr1, addr2)
	}

	if !bytes.Equal(bytecode1, bytecode2) {
		t.Fatal("bytecode mismatch between derivations")
	}

	if len(bytecode1) == 0 {
		t.Fatal("bytecode is empty")
	}

	if len(addr1) != 58 {
		t.Fatalf("address length = %d, want 58", len(addr1))
	}

	if bytes.Contains(bytecode1, pubkeyPlaceholder) {
		t.Fatal("public key placeholder was not patched")
	}

	if bytes.Contains(bytecode1, unlockPlaceholder) {
		t.Fatal("unlock_round placeholder was not patched")
	}

	if bytes.Contains(bytecode1, counterPattern) {
		t.Fatal("counter placeholder was not patched")
	}
}

func TestFalconTimelockSignatureRoundTrip(t *testing.T) {
	seed := make([]byte, 48)
	for i := range seed {
		seed[i] = byte(0xAA + i)
	}

	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	unlockRound := uint64(1000)
	bytecode, address, err := DeriveLsig(kp.PublicKey[:], unlockRound)
	if err != nil {
		t.Fatalf("DeriveLsig failed: %v", err)
	}

	genesisHash := make([]byte, 32)
	genesisHash[0] = 1

	sp := types.SuggestedParams{
		FlatFee:         true,
		Fee:             types.MicroAlgos(1000),
		FirstRoundValid: types.Round(unlockRound),
		LastRoundValid:  types.Round(unlockRound + 1000),
		GenesisID:       "testnet-v1.0",
		GenesisHash:     genesisHash,
	}

	txn, err := transaction.MakePaymentTxn(
		address,
		address,
		1,
		nil,
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn failed: %v", err)
	}

	txid := crypto.TransactionID(txn)
	sig, err := kp.Sign(txid)
	if err != nil {
		t.Fatalf("Falcon Sign failed: %v", err)
	}

	if err := falcongo.Verify(txid, falcon.CompressedSignature(sig), kp.PublicKey); err != nil {
		t.Fatalf("Falcon Verify failed: %v", err)
	}

	lsig := types.LogicSig{Logic: bytecode, Args: [][]byte{sig}}
	_, _, err = crypto.SignLogicSigTransaction(lsig, txn)
	if err != nil {
		t.Fatalf("SignLogicSigTransaction failed: %v", err)
	}
}

// TestFalconMessageDerivationGoldenVector verifies the message-to-sign derivation
// produces deterministic, known values. This catches drift in SDK or protocol changes.
//
// Golden vector:
//   - Fixed seed → deterministic Falcon keypair
//   - Fixed transaction params → deterministic transaction ID
//   - Transaction ID is what gets signed (32 bytes)
//   - TEAL's `txn TxID` must produce the same value
func TestFalconMessageDerivationGoldenVector(t *testing.T) {
	// Golden seed (deterministic keypair generation)
	seed := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	}

	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Golden public key hash (first 8 bytes for readability)
	// This verifies Falcon key derivation is deterministic
	pubKeyPrefix := fmt.Sprintf("%x", kp.PublicKey[:8])
	expectedPubKeyPrefix := "0a10e26f5266858d"
	if pubKeyPrefix != expectedPubKeyPrefix {
		t.Errorf("Public key prefix changed!\nGot:      %s\nExpected: %s\nThis indicates Falcon key derivation changed.", pubKeyPrefix, expectedPubKeyPrefix)
	}

	// Derive LogicSig address
	unlockRound := uint64(12345678)
	_, address, err := DeriveLsig(kp.PublicKey[:], unlockRound)
	if err != nil {
		t.Fatalf("DeriveLsig failed: %v", err)
	}

	// Golden genesis hash (32 bytes of 0x42)
	genesisHash := make([]byte, 32)
	for i := range genesisHash {
		genesisHash[i] = 0x42
	}

	sp := types.SuggestedParams{
		FlatFee:         true,
		Fee:             types.MicroAlgos(1000),
		FirstRoundValid: types.Round(unlockRound),
		LastRoundValid:  types.Round(unlockRound + 1000),
		GenesisID:       "golden-test-v1.0",
		GenesisHash:     genesisHash,
	}

	// Create payment transaction
	txn, err := transaction.MakePaymentTxn(
		address, // from LogicSig address
		address, // to same address (self-payment)
		1000000, // 1 Algo
		nil,     // no note
		"",      // no close-to
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn failed: %v", err)
	}

	// Golden transaction ID - this is what gets signed
	txid := crypto.TransactionID(txn)
	txidHex := fmt.Sprintf("%x", txid[:])

	// Verify transaction ID is deterministic
	// The txid depends on: sender, receiver, amount, fee, rounds, genesis
	expectedTxID := "9dcfd53bae362620f63cb0d98a4c336f547c912eda6d1e9440e7b14bbf300a6e"
	if txidHex != expectedTxID {
		t.Errorf("Transaction ID (message-to-sign) changed!\nGot:      %s\nExpected: %s\nThis indicates transaction encoding changed.", txidHex, expectedTxID)
	}

	// Verify LogicSig address is deterministic
	expectedAddress := "EGMKPN3CSA6PVIJ3IOLFAQBYL6YGQ54EIWZZRSUMIPTSRX32QRJXSUPG5U"
	if address != expectedAddress {
		t.Errorf("LogicSig address changed!\nGot:      %s\nExpected: %s\nThis indicates TEAL derivation changed.", address, expectedAddress)
	}

	t.Logf("Transaction ID (message-to-sign): %s", txidHex)
	t.Logf("LogicSig address: %s", address)

	// Sign the transaction ID (not the full transaction)
	sig, err := kp.Sign(txid)
	if err != nil {
		t.Fatalf("Falcon Sign failed: %v", err)
	}

	// Verify signature length (Falcon-1024 compressed signatures are variable, typically 1230-1280 bytes)
	if len(sig) < 1200 || len(sig) > 1300 {
		t.Errorf("Signature length out of expected range: got %d, expected 1200-1300", len(sig))
	}

	// Verify the signature is valid
	if err := falcongo.Verify(txid, falcon.CompressedSignature(sig), kp.PublicKey); err != nil {
		t.Fatalf("Falcon Verify failed: %v", err)
	}

	// Verify the same txid signed again produces a valid (possibly different) signature
	// Note: Falcon signatures may include randomness, so we verify correctness not equality
	sig2, err := kp.Sign(txid)
	if err != nil {
		t.Fatalf("Second Falcon Sign failed: %v", err)
	}
	if err := falcongo.Verify(txid, falcon.CompressedSignature(sig2), kp.PublicKey); err != nil {
		t.Fatalf("Second Falcon Verify failed: %v", err)
	}

	// Log the golden values for documentation
	t.Logf("=== GOLDEN TEST VECTOR ===")
	t.Logf("Seed (hex): %x", seed)
	t.Logf("Public key prefix: %s", pubKeyPrefix)
	t.Logf("LogicSig address: %s", address)
	t.Logf("Transaction ID (message): %s", txidHex)
	t.Logf("Signature length: %d bytes", len(sig))
}
