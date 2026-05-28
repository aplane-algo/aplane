// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"encoding/base64"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestWriteTransactionJSONDisabledReturnsEmpty(t *testing.T) {
	eng := &Engine{}
	filename, err := eng.WriteTransactionJSON(txnwriteTestPaymentTxn(1, 2), "TXID")
	if err != nil {
		t.Fatalf("WriteTransactionJSON() error = %v", err)
	}
	if filename != "" {
		t.Fatalf("filename = %q, want empty", filename)
	}
}

func TestWriteTransactionJSONWritesFormattedFileAndConvertsAddresses(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}

	eng := &Engine{WriteMode: true}
	txn := txnwriteTestPaymentTxn(1, 2)
	filename, err := eng.WriteTransactionJSON(txn, "TXID123")
	if err != nil {
		t.Fatalf("WriteTransactionJSON() error = %v", err)
	}
	if filename != "txnjson/TXID123.json" {
		t.Fatalf("filename = %q, want txnjson/TXID123.json", filename)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", filename, err)
	}
	text := string(data)
	if !strings.Contains(text, txn.Sender.String()) {
		t.Fatalf("output missing sender address %q:\n%s", txn.Sender.String(), text)
	}
	if !strings.Contains(text, txn.Receiver.String()) {
		t.Fatalf("output missing receiver address %q:\n%s", txn.Receiver.String(), text)
	}
}

func TestWriteTransactionJSONUsesSimulateSuffix(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}

	eng := &Engine{WriteMode: true, Simulate: true}
	filename, err := eng.WriteTransactionJSON(txnwriteTestPaymentTxn(1, 2), "SIMTX")
	if err != nil {
		t.Fatalf("WriteTransactionJSON() error = %v", err)
	}
	if filename != "txnjson/SIMTX.sim.json" {
		t.Fatalf("filename = %q, want txnjson/SIMTX.sim.json", filename)
	}
}

func TestWriteTxnCallbackReportsSuccessAndFailure(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		tmpDir := t.TempDir()
		oldDir, _ := os.Getwd()
		defer func() { _ = os.Chdir(oldDir) }()
		if err := os.Chdir(tmpDir); err != nil {
			t.Fatalf("Chdir() error = %v", err)
		}

		eng := &Engine{WriteMode: true}
		var notices []TransactionWriteNotice
		cb := eng.WriteTxnCallback(&notices)
		if cb == nil {
			t.Fatal("WriteTxnCallback() = nil, want callback")
		}
		cb(txnwriteTestPaymentTxn(1, 2), "TXNOTICE")
		if len(notices) != 1 || notices[0].Filename != "txnjson/TXNOTICE.json" || notices[0].Error != "" {
			t.Fatalf("notices = %#v, want saved notice", notices)
		}
	})

	t.Run("failure", func(t *testing.T) {
		tmpDir := t.TempDir()
		oldDir, _ := os.Getwd()
		defer func() { _ = os.Chdir(oldDir) }()
		if err := os.Chdir(tmpDir); err != nil {
			t.Fatalf("Chdir() error = %v", err)
		}

		eng := &Engine{WriteMode: true}
		var notices []TransactionWriteNotice
		cb := eng.WriteTxnCallback(&notices)
		cb(txnwriteTestPaymentTxn(1, 2), "bad/path")
		if len(notices) != 1 || !strings.Contains(notices[0].Error, "failed to write transaction file") {
			t.Fatalf("notices = %#v, want warning notice", notices)
		}
	})
}

func TestWriteTxnCallbackDisabledReturnsNil(t *testing.T) {
	eng := &Engine{}
	if cb := eng.WriteTxnCallback(nil); cb != nil {
		t.Fatal("WriteTxnCallback() should be nil when write mode is disabled")
	}
}

func TestConvertKnownAddressFieldsConvertsNestedAddressFields(t *testing.T) {
	sender := testAddrToAddress(1)
	receiver := testAddrToAddress(2)
	manager := testAddrToAddress(3)
	accountA := testAddrToAddress(4)
	accountB := testAddrToAddress(5)

	doc := map[string]interface{}{
		"snd": base64.StdEncoding.EncodeToString(sender[:]),
		"rcv": base64.StdEncoding.EncodeToString(receiver[:]),
		"apar": map[string]interface{}{
			"m": base64.StdEncoding.EncodeToString(manager[:]),
			"x": "leave-me-alone",
		},
		"apat": []interface{}{
			base64.StdEncoding.EncodeToString(accountA[:]),
			base64.StdEncoding.EncodeToString(accountB[:]),
			"not-an-address",
		},
	}

	convertKnownAddressFields(doc)

	if got := doc["snd"]; got != sender.String() {
		t.Fatalf("snd = %v, want %s", got, sender.String())
	}
	if got := doc["rcv"]; got != receiver.String() {
		t.Fatalf("rcv = %v, want %s", got, receiver.String())
	}
	apar := doc["apar"].(map[string]interface{})
	if got := apar["m"]; got != manager.String() {
		t.Fatalf("apar[m] = %v, want %s", got, manager.String())
	}
	if got := apar["x"]; got != "leave-me-alone" {
		t.Fatalf("apar[x] = %v, want original value", got)
	}
	accounts := doc["apat"].([]interface{})
	wantAccounts := []interface{}{accountA.String(), accountB.String(), "not-an-address"}
	if !reflect.DeepEqual(accounts, wantAccounts) {
		t.Fatalf("apat = %#v, want %#v", accounts, wantAccounts)
	}
}

func TestBase64ToBase32AddressInvalidInputsReturnEmpty(t *testing.T) {
	tests := []string{
		"",
		"%%%not-base64%%%",
		base64.StdEncoding.EncodeToString([]byte("too short")),
	}

	for _, input := range tests {
		if got := base64ToBase32Address(input); got != "" {
			t.Fatalf("base64ToBase32Address(%q) = %q, want empty", input, got)
		}
	}
}

func TestWriteTransactionJSONConvertsNestedTransactionAddresses(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}

	manager := testAddrToAddress(10)
	reserve := testAddrToAddress(11)
	appAcct := testAddrToAddress(12)

	eng := &Engine{WriteMode: true}

	assetTxn := types.Transaction{
		Type: types.AssetConfigTx,
		Header: types.Header{
			Sender:      testAddrToAddress(9),
			Fee:         types.MicroAlgos(1000),
			FirstValid:  types.Round(1),
			LastValid:   types.Round(100),
			GenesisHash: [32]byte{1, 2, 3},
			GenesisID:   "testnet-v1.0",
		},
		AssetConfigTxnFields: types.AssetConfigTxnFields{
			AssetParams: types.AssetParams{
				Manager: manager,
				Reserve: reserve,
			},
		},
	}
	filename, err := eng.WriteTransactionJSON(assetTxn, "ASSETTX")
	if err != nil {
		t.Fatalf("WriteTransactionJSON(asset) error = %v", err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", filename, err)
	}
	text := string(data)
	if !strings.Contains(text, manager.String()) || !strings.Contains(text, reserve.String()) {
		t.Fatalf("asset JSON missing converted nested addresses:\n%s", text)
	}

	appTxn := types.Transaction{
		Type: types.ApplicationCallTx,
		Header: types.Header{
			Sender:      testAddrToAddress(13),
			Fee:         types.MicroAlgos(1000),
			FirstValid:  types.Round(1),
			LastValid:   types.Round(100),
			GenesisHash: [32]byte{1, 2, 3},
			GenesisID:   "testnet-v1.0",
		},
		ApplicationFields: types.ApplicationFields{
			ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				ApplicationID: 1,
				Accounts:      []types.Address{appAcct},
			},
		},
	}
	filename, err = eng.WriteTransactionJSON(appTxn, "APPTX")
	if err != nil {
		t.Fatalf("WriteTransactionJSON(app) error = %v", err)
	}
	data, err = os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", filename, err)
	}
	if !strings.Contains(string(data), appAcct.String()) {
		t.Fatalf("app JSON missing converted app account address:\n%s", string(data))
	}
}

func txnwriteTestPaymentTxn(senderIndex, receiverIndex int) types.Transaction {
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      testAddrToAddress(senderIndex),
			Fee:         types.MicroAlgos(1000),
			FirstValid:  types.Round(1),
			LastValid:   types.Round(100),
			GenesisHash: [32]byte{1, 2, 3},
			GenesisID:   "testnet-v1.0",
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: testAddrToAddress(receiverIndex),
			Amount:   types.MicroAlgos(1000),
		},
	}
}

func testAddrToAddress(index int) types.Address {
	addr, err := types.DecodeAddress(testAddr(index))
	if err != nil {
		panic(err)
	}
	return addr
}
