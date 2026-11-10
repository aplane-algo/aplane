// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package algo

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func parserTestPayment(t *testing.T, amount uint64) types.Transaction {
	t.Helper()
	var sender types.Address
	sender[0] = 1
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:     sender,
			Fee:        1000,
			FirstValid: 1,
			LastValid:  1000,
		},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: sender, Amount: types.MicroAlgos(amount)},
	}
}

func TestParseTransactionMsgpackReadsEveryConcatenatedTransaction(t *testing.T) {
	first := msgpack.Encode(parserTestPayment(t, 1))
	second := msgpack.Encode(parserTestPayment(t, 2))

	txns, err := ParseTransactionMsgpack(append(append([]byte{}, first...), second...))
	if err != nil {
		t.Fatalf("two concatenated transactions: %v", err)
	}
	if len(txns) != 2 || txns[0].Amount != 1 || txns[1].Amount != 2 {
		t.Fatalf("parsed %d transaction(s): %+v", len(txns), txns)
	}

	array := msgpack.Encode([]types.Transaction{parserTestPayment(t, 1), parserTestPayment(t, 2)})
	if txns, err = ParseTransactionMsgpack(array); err != nil || len(txns) != 2 {
		t.Fatalf("array of two: %d transaction(s), %v", len(txns), err)
	}
}

func TestParseTransactionMsgpackRefusesLeftoverAndNonCanonicalBytes(t *testing.T) {
	first := msgpack.Encode(parserTestPayment(t, 1))
	array := msgpack.Encode([]types.Transaction{parserTestPayment(t, 1)})

	// The same payment with its amount written twice: 1, then 5,000,000.
	// A decoder keeps the last one.
	var fields map[string]interface{}
	if err := msgpack.Decode(first, &fields); err != nil {
		t.Fatal(err)
	}
	duplicated := append([]byte{first[0] + 1}, first[1:]...)
	duplicated = append(duplicated, msgpack.Encode(map[string]uint64{"amt": 5_000_000})[1:]...)
	var probe types.Transaction
	if err := msgpack.Decode(duplicated, &probe); err != nil || probe.Amount != 5_000_000 {
		t.Fatalf("fixture: duplicate-key payment decoded to amount %d, %v", probe.Amount, err)
	}

	cases := map[string][]byte{
		"empty":                        {},
		"trailing garbage":             append(append([]byte{}, first...), 0xc1, 0xff),
		"trailing text":                append(append([]byte{}, first...), []byte("garbage")...),
		"array with trailing bytes":    append(append([]byte{}, array...), first...),
		"repeated field":               duplicated,
		"second transaction truncated": append(append([]byte{}, first...), first[:len(first)-3]...),
	}
	for name, data := range cases {
		if txns, err := ParseTransactionMsgpack(data); err == nil {
			t.Errorf("%s: parsed %d transaction(s), want refused", name, len(txns))
		}
	}
}

func TestParseTransactionsRefusesDuplicateJSONKeys(t *testing.T) {
	txn := parserTestPayment(t, 1)
	single := string(sdkjson.Encode(txn))
	if _, err := ParseTransactions([]byte(single)); err != nil {
		t.Fatalf("plain JSON transaction: %v", err)
	}

	b64 := base64.StdEncoding.EncodeToString(msgpack.Encode(txn))
	cases := map[string]string{
		"repeated amount":          strings.Replace(single, `"amt": 1,`, `"amt": 1, "amt": 5000000,`, 1),
		"repeated txn list":        `{"txn":["` + b64 + `"],"txn":["` + b64 + `"]}`,
		"trailing document":        single + single,
		"repeated key in an array": "[" + strings.Replace(single, `"amt": 1,`, `"amt": 1, "amt": 2,`, 1) + "]",
	}
	for name, data := range cases {
		if !strings.Contains(single, `"amt": 1,`) {
			t.Fatalf("fixture: encoded payment has no amt field: %s", single)
		}
		if txns, err := ParseTransactions([]byte(data)); err == nil {
			t.Errorf("%s: parsed %d transaction(s), want refused", name, len(txns))
		}
	}

	nonCanonical := append(msgpack.Encode(txn), 0xc0)
	wrapped := `{"txn":["` + base64.StdEncoding.EncodeToString(nonCanonical) + `"]}`
	if txns, err := ParseTransactions([]byte(wrapped)); err == nil {
		t.Errorf("txn list entry with trailing bytes: parsed %d transaction(s), want refused", len(txns))
	}
}
