// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package algo

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sdkjson "github.com/algorand/go-algorand-sdk/v2/encoding/json"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestParseTransactions_JSON_SingleTxn(t *testing.T) {
	// Create a simple payment transaction for testing
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Fee:         types.MicroAlgos(1000),
			FirstValid:  types.Round(1000),
			LastValid:   types.Round(2000),
			GenesisHash: [32]byte{1, 2, 3},
			GenesisID:   "testnet-v1.0",
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Amount: types.MicroAlgos(100000),
		},
	}

	// Use SDK's JSON encoder which handles canonical format
	jsonData := sdkjson.Encode(txn)

	result, err := ParseTransactions(jsonData)
	if err != nil {
		t.Fatalf("ParseTransactions() error = %v", err)
	}

	if len(result) != 1 {
		t.Errorf("ParseTransactions() returned %d transactions, want 1", len(result))
	}

	if result[0].Type != types.PaymentTx {
		t.Errorf("ParseTransactions() transaction type = %v, want %v", result[0].Type, types.PaymentTx)
	}
}

func TestParseTransactions_JSON_WithTxnArray(t *testing.T) {
	// Create a transaction
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Fee:         types.MicroAlgos(1000),
			FirstValid:  types.Round(1000),
			LastValid:   types.Round(2000),
			GenesisHash: [32]byte{1, 2, 3},
		},
	}

	// Encode to msgpack then base64
	msgpackData := msgpack.Encode(txn)
	b64Txn := base64.StdEncoding.EncodeToString(msgpackData)

	// Create JSON file format with txn array
	jsonObj := map[string][]string{
		"txn": {b64Txn},
	}
	jsonData, _ := json.Marshal(jsonObj)

	result, err := ParseTransactions(jsonData)
	if err != nil {
		t.Fatalf("ParseTransactions() error = %v", err)
	}

	if len(result) != 1 {
		t.Errorf("ParseTransactions() returned %d transactions, want 1", len(result))
	}
}

func TestParseTransactions_Base64(t *testing.T) {
	// Create a transaction
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Fee:         types.MicroAlgos(1000),
			FirstValid:  types.Round(1000),
			LastValid:   types.Round(2000),
			GenesisHash: [32]byte{1, 2, 3},
		},
	}

	// Encode to msgpack then base64
	msgpackData := msgpack.Encode(txn)
	b64Data := base64.StdEncoding.EncodeToString(msgpackData)

	result, err := ParseTransactions([]byte(b64Data))
	if err != nil {
		t.Fatalf("ParseTransactions() error = %v", err)
	}

	if len(result) != 1 {
		t.Errorf("ParseTransactions() returned %d transactions, want 1", len(result))
	}
}

func TestParseTransactions_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"invalid json", []byte(`{invalid`)},
		{"invalid base64", []byte(`not-valid-base64!@#$`)},
		{"empty array json", []byte(`[]`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTransactions(tt.data)
			if err == nil {
				t.Error("ParseTransactions() expected error, got nil")
			}
		})
	}
}

func TestParseTransactionFile(t *testing.T) {
	// Create a temp file with a valid transaction
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Fee:         types.MicroAlgos(1000),
			FirstValid:  types.Round(1000),
			LastValid:   types.Round(2000),
			GenesisHash: [32]byte{1, 2, 3},
		},
	}

	msgpackData := msgpack.Encode(txn)
	b64Data := base64.StdEncoding.EncodeToString(msgpackData)

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txn")
	if err := os.WriteFile(tmpFile, []byte(b64Data), 0600); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	result, err := ParseTransactionFile(tmpFile)
	if err != nil {
		t.Fatalf("ParseTransactionFile() error = %v", err)
	}

	if len(result) != 1 {
		t.Errorf("ParseTransactionFile() returned %d transactions, want 1", len(result))
	}
}

func TestParseTransactionFile_NotExists(t *testing.T) {
	_, err := ParseTransactionFile("/nonexistent/path/to/file.txn")
	if err == nil {
		t.Error("ParseTransactionFile() expected error for non-existent file, got nil")
	}
}

func TestParseTransactionMsgpack_SingleTxn(t *testing.T) {
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Fee:         types.MicroAlgos(1000),
			FirstValid:  types.Round(1000),
			LastValid:   types.Round(2000),
			GenesisHash: [32]byte{1, 2, 3},
		},
	}

	msgpackData := msgpack.Encode(txn)

	result, err := ParseTransactionMsgpack(msgpackData)
	if err != nil {
		t.Fatalf("ParseTransactionMsgpack() error = %v", err)
	}

	if len(result) != 1 {
		t.Errorf("ParseTransactionMsgpack() returned %d transactions, want 1", len(result))
	}
}

func TestParseTransactionMsgpack_Invalid(t *testing.T) {
	_, err := ParseTransactionMsgpack([]byte("invalid msgpack data"))
	if err == nil {
		t.Error("ParseTransactionMsgpack() expected error, got nil")
	}
}
