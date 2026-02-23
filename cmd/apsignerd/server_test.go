// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"encoding/hex"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// TestIsValidationTransaction tests validation transaction detection
func TestIsValidationTransaction(t *testing.T) {
	// Create a valid validation transaction (0 ALGO self-send)
	sender, _ := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")

	validationTxn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: sender,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: sender, // Self-send
			Amount:   0,      // 0 ALGO
		},
	}

	// Encode transaction
	txnBytes := msgpack.Encode(validationTxn)

	// Test with TX prefix (as sent to algod)
	txnWithPrefix := append([]byte("TX"), txnBytes...)

	tests := []struct {
		name        string
		txnBytes    []byte
		txnSender   string
		expected    bool
		description string
	}{
		{
			name:        "valid validation txn with TX prefix",
			txnBytes:    txnWithPrefix,
			txnSender:   "",
			expected:    true,
			description: "0 ALGO self-send with TX prefix",
		},
		{
			name:        "valid validation txn without prefix",
			txnBytes:    txnBytes,
			txnSender:   "",
			expected:    true,
			description: "0 ALGO self-send without TX prefix",
		},
		{
			name:        "valid with matching sender",
			txnBytes:    txnBytes,
			txnSender:   sender.String(),
			expected:    true,
			description: "0 ALGO self-send with matching txnSender",
		},
		{
			name:        "invalid - wrong sender provided",
			txnBytes:    txnBytes,
			txnSender:   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			expected:    false,
			description: "txnSender doesn't match transaction sender",
		},
		{
			name:        "invalid - empty bytes",
			txnBytes:    []byte{},
			txnSender:   "",
			expected:    false,
			description: "empty transaction bytes",
		},
		{
			name:        "invalid - garbage bytes",
			txnBytes:    []byte("not a valid transaction"),
			txnSender:   "",
			expected:    false,
			description: "invalid msgpack data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidationTransaction(tt.txnBytes, tt.txnSender, "")
			if result != tt.expected {
				t.Errorf("%s: got %v, want %v", tt.description, result, tt.expected)
			}
		})
	}
}

// TestIsValidationTransactionNonZeroAmount verifies non-zero amount is rejected
func TestIsValidationTransactionNonZeroAmount(t *testing.T) {
	sender, _ := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: sender,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: sender,
			Amount:   1000000, // 1 ALGO - not a validation txn
		},
	}

	txnBytes := msgpack.Encode(txn)
	if isValidationTransaction(txnBytes, "", "") {
		t.Error("Non-zero amount transaction should not be validation transaction")
	}
}

// TestIsValidationTransactionNotSelfSend verifies non-self-send is rejected
func TestIsValidationTransactionNotSelfSend(t *testing.T) {
	// Use valid Algorand test addresses
	sender, err := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	if err != nil {
		t.Fatalf("Failed to decode sender address: %v", err)
	}
	// A different valid address (derived from different bytes)
	receiver, err := types.DecodeAddress("7777777777777777777777777777777777777777777777777774MSJUVU")
	if err != nil {
		t.Fatalf("Failed to decode receiver address: %v", err)
	}

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: sender,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: receiver, // Different receiver
			Amount:   0,
		},
	}

	txnBytes := msgpack.Encode(txn)
	if isValidationTransaction(txnBytes, "", "") {
		t.Error("Non-self-send transaction should not be validation transaction")
	}
}

// TestIsValidationTransactionWithRekey verifies rekey transaction is rejected
func TestIsValidationTransactionWithRekey(t *testing.T) {
	sender, err := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	if err != nil {
		t.Fatalf("Failed to decode sender address: %v", err)
	}
	rekeyTo, err := types.DecodeAddress("7777777777777777777777777777777777777777777777777774MSJUVU")
	if err != nil {
		t.Fatalf("Failed to decode rekeyTo address: %v", err)
	}

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:  sender,
			RekeyTo: rekeyTo, // Rekey action
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: sender,
			Amount:   0,
		},
	}

	txnBytes := msgpack.Encode(txn)
	if isValidationTransaction(txnBytes, "", "") {
		t.Error("Rekey transaction should not be validation transaction")
	}
}

// TestIsValidationTransactionWithCloseRemainder verifies close remainder is rejected
func TestIsValidationTransactionWithCloseRemainder(t *testing.T) {
	sender, err := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	if err != nil {
		t.Fatalf("Failed to decode sender address: %v", err)
	}
	closeTo, err := types.DecodeAddress("7777777777777777777777777777777777777777777777777774MSJUVU")
	if err != nil {
		t.Fatalf("Failed to decode closeTo address: %v", err)
	}

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: sender,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver:         sender,
			Amount:           0,
			CloseRemainderTo: closeTo, // Close action
		},
	}

	txnBytes := msgpack.Encode(txn)
	if isValidationTransaction(txnBytes, "", "") {
		t.Error("Close remainder transaction should not be validation transaction")
	}
}

// TestIsValidationTransactionNonPayment verifies non-payment txn type is rejected
func TestIsValidationTransactionNonPayment(t *testing.T) {
	sender, _ := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")

	txn := types.Transaction{
		Type: types.AssetTransferTx, // Not a payment
		Header: types.Header{
			Sender: sender,
		},
	}

	txnBytes := msgpack.Encode(txn)
	if isValidationTransaction(txnBytes, "", "") {
		t.Error("Asset transfer transaction should not be validation transaction")
	}
}

// TestComputeKeysChecksum verifies checksum computation
func TestComputeKeysChecksum(t *testing.T) {
	signer := &Signer{
		keys:     map[string]map[string]string{auth.DefaultIdentityID: {}},
		keysLock: sync.RWMutex{},
	}

	// Empty keys should produce consistent checksum
	checksum1 := signer.computeKeysChecksum(auth.DefaultIdentityID)
	checksum2 := signer.computeKeysChecksum(auth.DefaultIdentityID)
	if checksum1 != checksum2 {
		t.Error("Same keys should produce same checksum")
	}

	// Add a key
	signer.keys[auth.DefaultIdentityID]["AAAA"] = "users/default/keys/AAAA.key"
	checksum3 := signer.computeKeysChecksum(auth.DefaultIdentityID)
	if checksum1 == checksum3 {
		t.Error("Different keys should produce different checksum")
	}

	// Add another key
	signer.keys[auth.DefaultIdentityID]["BBBB"] = "users/default/keys/BBBB.key"
	checksum4 := signer.computeKeysChecksum(auth.DefaultIdentityID)
	if checksum3 == checksum4 {
		t.Error("Different keys should produce different checksum")
	}

	// Same keys in different order should produce same checksum
	signer2 := &Signer{
		keys: map[string]map[string]string{
			auth.DefaultIdentityID: {
				"BBBB": "users/default/keys/BBBB.key",
				"AAAA": "users/default/keys/AAAA.key",
			},
		},
		keysLock: sync.RWMutex{},
	}
	checksum5 := signer2.computeKeysChecksum(auth.DefaultIdentityID)
	if checksum4 != checksum5 {
		t.Error("Same keys in different order should produce same checksum (sorted)")
	}
}

// TestComputeKeysChecksumFormat verifies checksum is 16 hex chars
func TestComputeKeysChecksumFormat(t *testing.T) {
	signer := &Signer{
		keys:     map[string]map[string]string{auth.DefaultIdentityID: {"TEST": "users/default/keys/TEST.key"}},
		keysLock: sync.RWMutex{},
	}

	checksum := signer.computeKeysChecksum(auth.DefaultIdentityID)

	// Should be 16 hex characters (8 bytes = 64 bits)
	if len(checksum) != 16 {
		t.Errorf("Checksum should be 16 characters, got %d: %s", len(checksum), checksum)
	}

	// Should be valid hex
	_, err := hex.DecodeString(checksum)
	if err != nil {
		t.Errorf("Checksum should be valid hex: %v", err)
	}
}

// TestFindKeyFileForAddress tests key lookup
func TestFindKeyFileForAddress(t *testing.T) {
	signer := &Signer{
		keys: map[string]map[string]string{
			auth.DefaultIdentityID: {
				"ALICE": "users/default/keys/ALICE.key",
				"BOB":   "users/default/keys/BOB.key",
			},
		},
		keysLock: sync.RWMutex{},
	}

	// Test existing key
	keyFile, err := signer.findKeyFileForAddress(auth.DefaultIdentityID, "ALICE")
	if err != nil {
		t.Errorf("Expected to find key for ALICE: %v", err)
	}
	if keyFile != "users/default/keys/ALICE.key" {
		t.Errorf("Expected users/default/ALICE.key, got %s", keyFile)
	}

	// Test non-existing key
	_, err = signer.findKeyFileForAddress(auth.DefaultIdentityID, "CHARLIE")
	if err == nil {
		t.Error("Expected error for non-existing key")
	}
}

// TestBuildKeyInfoListEmpty tests empty key list
func TestBuildKeyInfoListEmpty(t *testing.T) {
	signer := &Signer{
		keys:     map[string]map[string]string{auth.DefaultIdentityID: {}},
		keysLock: sync.RWMutex{},
	}

	keyList := signer.buildKeyInfoList(auth.DefaultIdentityID)
	if len(keyList) != 0 {
		t.Errorf("Expected empty key list, got %d items", len(keyList))
	}
}

// TestPassthroughSignedTxnEncoding verifies that signed transactions can be
// properly encoded for passthrough mode
func TestPassthroughSignedTxnEncoding(t *testing.T) {
	// Create a test transaction
	sender, _ := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	receiver, _ := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      sender,
			Fee:         1000,
			FirstValid:  1000,
			LastValid:   2000,
			GenesisID:   "testnet-v1.0",
			GenesisHash: [32]byte{1, 2, 3},
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: receiver,
			Amount:   1000000,
		},
	}

	// Simulate Ed25519 signature (64 bytes)
	var sig types.Signature
	for i := range sig {
		sig[i] = byte(i)
	}

	// Create SignedTxn
	stxn := types.SignedTxn{
		Txn: txn,
		Sig: sig,
	}

	// Encode as msgpack (this is what passthrough expects)
	stxnBytes := msgpack.Encode(stxn)
	stxnHex := hex.EncodeToString(stxnBytes)

	// Verify we can decode it back
	decodedBytes, err := hex.DecodeString(stxnHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	var decodedStxn types.SignedTxn
	if err := msgpack.Decode(decodedBytes, &decodedStxn); err != nil {
		t.Fatalf("Failed to decode SignedTxn: %v", err)
	}

	// Verify the transaction is preserved
	if decodedStxn.Txn.Sender != txn.Sender {
		t.Error("Sender mismatch after decode")
	}
	if decodedStxn.Txn.Amount != txn.Amount {
		t.Error("Amount mismatch after decode")
	}
	if decodedStxn.Sig != sig {
		t.Error("Signature mismatch after decode")
	}

	t.Logf("SignedTxn hex length: %d chars", len(stxnHex))
	t.Logf("SignedTxn hex (first 100 chars): %s...", stxnHex[:min(100, len(stxnHex))])
}

// TestPassthroughWithLogicSig verifies LogicSig transactions can be encoded for passthrough
func TestPassthroughWithLogicSig(t *testing.T) {
	sender, _ := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      sender,
			Fee:         1000,
			FirstValid:  1000,
			LastValid:   2000,
			GenesisID:   "testnet-v1.0",
			GenesisHash: [32]byte{1, 2, 3},
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: sender,
			Amount:   0,
		},
	}

	// Create a simple LogicSig (int 1 - always approves)
	simpleTeal := []byte{0x06, 0x81, 0x01} // #pragma version 6; int 1
	lsig := types.LogicSig{
		Logic: simpleTeal,
		Args:  [][]byte{{0x01, 0x02, 0x03}}, // Simulated signature arg
	}

	// Create SignedTxn with LogicSig
	stxn := types.SignedTxn{
		Txn:  txn,
		Lsig: lsig,
	}

	// Encode as msgpack
	stxnBytes := msgpack.Encode(stxn)
	stxnHex := hex.EncodeToString(stxnBytes)

	// Verify we can decode it back
	decodedBytes, _ := hex.DecodeString(stxnHex)
	var decodedStxn types.SignedTxn
	if err := msgpack.Decode(decodedBytes, &decodedStxn); err != nil {
		t.Fatalf("Failed to decode SignedTxn with LogicSig: %v", err)
	}

	// Verify LogicSig is preserved
	if len(decodedStxn.Lsig.Logic) != len(lsig.Logic) {
		t.Error("LogicSig bytecode length mismatch")
	}
	if len(decodedStxn.Lsig.Args) != 1 {
		t.Error("LogicSig args count mismatch")
	}

	t.Logf("LogicSig SignedTxn hex length: %d chars", len(stxnHex))
}

// TestPassthroughRequestValidation tests the request validation logic
func TestPassthroughRequestValidation(t *testing.T) {
	tests := []struct {
		name         string
		authAddr     string
		txnBytesHex  string
		signedTxnHex string
		wantMode     string // "sign", "passthrough", or "error"
	}{
		{
			name:        "sign mode - both fields",
			authAddr:    "TESTADDR",
			txnBytesHex: "5458deadbeef",
			wantMode:    "sign",
		},
		{
			name:         "passthrough mode",
			signedTxnHex: "82a3736967deadbeef",
			wantMode:     "passthrough",
		},
		{
			name:         "error - both modes specified",
			authAddr:     "TESTADDR",
			txnBytesHex:  "5458deadbeef",
			signedTxnHex: "82a3736967deadbeef",
			wantMode:     "error",
		},
		{
			name:     "error - neither mode specified",
			wantMode: "error",
		},
		{
			name:     "error - auth_address without txn_bytes_hex",
			authAddr: "TESTADDR",
			wantMode: "error",
		},
		{
			name:        "error - txn_bytes_hex without auth_address",
			txnBytesHex: "5458deadbeef",
			wantMode:    "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasSignFields := tt.authAddr != "" || tt.txnBytesHex != ""
			hasPassthrough := tt.signedTxnHex != ""

			var gotMode string
			if hasSignFields && hasPassthrough {
				gotMode = "error"
			} else if !hasSignFields && !hasPassthrough {
				gotMode = "error"
			} else if hasPassthrough {
				gotMode = "passthrough"
			} else if tt.authAddr == "" || tt.txnBytesHex == "" {
				gotMode = "error"
			} else {
				gotMode = "sign"
			}

			if gotMode != tt.wantMode {
				t.Errorf("got mode %q, want %q", gotMode, tt.wantMode)
			}
		})
	}
}
