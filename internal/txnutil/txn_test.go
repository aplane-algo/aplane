// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnutil

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestEncodeDecodePrefixedHexRoundTrip(t *testing.T) {
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      types.Address{1, 2, 3},
			Fee:         1000,
			FirstValid:  10,
			LastValid:   20,
			Note:        []byte("hello"),
			GenesisID:   "testnet-v1.0",
			GenesisHash: [32]byte{9, 8, 7},
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{4, 5, 6},
			Amount:   42,
		},
	}

	encoded := EncodeWithPrefixHex(txn)
	decoded, err := DecodePrefixedHex(encoded)
	if err != nil {
		t.Fatalf("DecodePrefixedHex() error = %v", err)
	}

	if decoded.Type != txn.Type {
		t.Fatalf("Type = %v, want %v", decoded.Type, txn.Type)
	}
	if decoded.Sender != txn.Sender {
		t.Fatalf("Sender = %v, want %v", decoded.Sender, txn.Sender)
	}
	if decoded.Fee != txn.Fee {
		t.Fatalf("Fee = %d, want %d", decoded.Fee, txn.Fee)
	}
	if decoded.FirstValid != txn.FirstValid {
		t.Fatalf("FirstValid = %d, want %d", decoded.FirstValid, txn.FirstValid)
	}
	if decoded.LastValid != txn.LastValid {
		t.Fatalf("LastValid = %d, want %d", decoded.LastValid, txn.LastValid)
	}
	if string(decoded.Note) != string(txn.Note) {
		t.Fatalf("Note = %q, want %q", decoded.Note, txn.Note)
	}
	if decoded.GenesisID != txn.GenesisID {
		t.Fatalf("GenesisID = %q, want %q", decoded.GenesisID, txn.GenesisID)
	}
	if decoded.GenesisHash != txn.GenesisHash {
		t.Fatalf("GenesisHash = %v, want %v", decoded.GenesisHash, txn.GenesisHash)
	}
	if decoded.Receiver != txn.Receiver {
		t.Fatalf("Receiver = %v, want %v", decoded.Receiver, txn.Receiver)
	}
	if decoded.Amount != txn.Amount {
		t.Fatalf("Amount = %d, want %d", decoded.Amount, txn.Amount)
	}
}

func TestDecodePrefixedHexRejectsMissingPrefix(t *testing.T) {
	_, err := DecodePrefixedHex("80")
	if err == nil {
		t.Fatal("expected error for missing TX prefix")
	}
	if !strings.Contains(err.Error(), "missing TX prefix") {
		t.Fatalf("error = %v, want missing TX prefix", err)
	}
}

func TestDecodePrefixedHexRejectsInvalidHex(t *testing.T) {
	_, err := DecodePrefixedHex("not-hex")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
	if !strings.Contains(err.Error(), "invalid planned txn hex") {
		t.Fatalf("error = %v, want invalid planned txn hex", err)
	}
}
