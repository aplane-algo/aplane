// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	sdkjson "github.com/algorand/go-algorand-sdk/v2/encoding/json"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/algo"
)

func TestWriteTransactionJSONDisabledReturnsEmpty(t *testing.T) {
	eng := &Engine{Core: &Core{}}
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

	eng := &Engine{Core: &Core{WriteMode: true}}
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

	eng := &Engine{Core: &Core{WriteMode: true, Simulate: true}}
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

		eng := &Engine{Core: &Core{WriteMode: true}}
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

		eng := &Engine{Core: &Core{WriteMode: true}}
		var notices []TransactionWriteNotice
		cb := eng.WriteTxnCallback(&notices)
		cb(txnwriteTestPaymentTxn(1, 2), "bad/path")
		if len(notices) != 1 || !strings.Contains(notices[0].Error, "failed to write transaction file") {
			t.Fatalf("notices = %#v, want warning notice", notices)
		}
	})
}

func TestWriteTxnCallbackDisabledReturnsNil(t *testing.T) {
	eng := &Engine{Core: &Core{}}
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

	eng := &Engine{Core: &Core{WriteMode: true}}

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

func TestWriteTransactionJSONWritesLargeNumbersDigitForDigit(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}

	// Past 2^53 a float64 holds only even numbers, so this one would be
	// written as 10000000000000000.
	const pastFloat = uint64(10_000_000_000_000_001)
	const maxUint64 = uint64(math.MaxUint64)
	sender := testAddrToAddress(1)
	receiver := testAddrToAddress(2)
	header := types.Header{
		Sender:      sender,
		Fee:         types.MicroAlgos(pastFloat),
		FirstValid:  types.Round(pastFloat),
		LastValid:   types.Round(maxUint64),
		GenesisHash: [32]byte{1, 2, 3},
		GenesisID:   "testnet-v1.0",
	}
	digits := func(n uint64) string { return strconv.FormatUint(n, 10) }

	cases := []struct {
		name    string
		txn     types.Transaction
		numbers map[string]string
		addrs   map[string]string
	}{
		{
			name: "payment",
			txn: types.Transaction{
				Type:             types.PaymentTx,
				Header:           header,
				PaymentTxnFields: types.PaymentTxnFields{Receiver: receiver, Amount: types.MicroAlgos(maxUint64)},
			},
			numbers: map[string]string{
				"amt": digits(maxUint64), "fee": digits(pastFloat), "fv": digits(pastFloat), "lv": digits(maxUint64),
			},
			addrs: map[string]string{"snd": sender.String(), "rcv": receiver.String()},
		},
		{
			name: "asset transfer",
			txn: types.Transaction{
				Type:   types.AssetTransferTx,
				Header: header,
				AssetTransferTxnFields: types.AssetTransferTxnFields{
					XferAsset: types.AssetIndex(pastFloat), AssetAmount: maxUint64, AssetReceiver: receiver,
				},
			},
			numbers: map[string]string{"aamt": digits(maxUint64), "xaid": digits(pastFloat)},
			addrs:   map[string]string{"snd": sender.String(), "arcv": receiver.String()},
		},
		{
			name: "asset config",
			txn: types.Transaction{
				Type:   types.AssetConfigTx,
				Header: header,
				AssetConfigTxnFields: types.AssetConfigTxnFields{
					AssetParams: types.AssetParams{Total: maxUint64, Manager: receiver},
				},
			},
			numbers: map[string]string{"apar.t": digits(maxUint64), "lv": digits(maxUint64)},
			addrs:   map[string]string{"snd": sender.String(), "apar.m": receiver.String()},
		},
	}

	eng := &Engine{Core: &Core{WriteMode: true}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filename, err := eng.WriteTransactionJSON(tc.txn, "BIG")
			if err != nil {
				t.Fatalf("WriteTransactionJSON() error = %v", err)
			}
			data, err := os.ReadFile(filename)
			if err != nil {
				t.Fatalf("ReadFile(%q) error = %v", filename, err)
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.UseNumber()
			var doc map[string]interface{}
			if err := decoder.Decode(&doc); err != nil {
				t.Fatalf("decode written file: %v\n%s", err, data)
			}
			for path, want := range tc.numbers {
				got, ok := txnwriteLookup(doc, path).(json.Number)
				if !ok || got.String() != want {
					t.Errorf("%s = %v, want %s\n%s", path, txnwriteLookup(doc, path), want, data)
				}
			}
			for path, want := range tc.addrs {
				if got := txnwriteLookup(doc, path); got != want {
					t.Errorf("%s = %v, want base32 %s", path, got, want)
				}
			}

			var back types.Transaction
			if err := sdkjson.Decode(data, &back); err != nil {
				t.Fatalf("SDK decode of written file: %v\n%s", err, data)
			}
			if !bytes.Equal(msgpack.Encode(back), msgpack.Encode(tc.txn)) {
				t.Fatalf("written file decodes to another transaction:\n%s", data)
			}
		})
	}
}

// txnwriteLookup follows a dotted path of object keys.
func txnwriteLookup(doc map[string]interface{}, path string) interface{} {
	var value interface{} = doc
	for _, key := range strings.Split(path, ".") {
		object, ok := value.(map[string]interface{})
		if !ok {
			return nil
		}
		value = object[key]
	}
	return value
}

func TestWriteTransactionJSONFileReadsBackAsTheSameTransaction(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}

	header := types.Header{
		Sender:      testAddrToAddress(1),
		Fee:         types.MicroAlgos(math.MaxUint64),
		FirstValid:  types.Round(10_000_000_000_000_001),
		LastValid:   types.Round(math.MaxUint64),
		Note:        []byte("note"),
		GenesisID:   "testnet-v1.0",
		GenesisHash: [32]byte{1, 2, 3},
		Group:       [32]byte{4},
		Lease:       [32]byte{5},
		RekeyTo:     testAddrToAddress(2),
	}
	var keyreg types.KeyregTxnFields
	for i := range keyreg.VotePK {
		keyreg.VotePK[i], keyreg.SelectionPK[i] = byte(i+1), byte(i+2)
	}
	keyreg.StateProofPK[63] = 9
	keyreg.VoteFirst, keyreg.VoteLast, keyreg.VoteKeyDilution = 1, 3_000_000, 1733

	txns := map[string]types.Transaction{
		"payment": {Type: types.PaymentTx, Header: header, PaymentTxnFields: types.PaymentTxnFields{
			Receiver: testAddrToAddress(3), Amount: math.MaxUint64, CloseRemainderTo: testAddrToAddress(4),
		}},
		"keyreg": {Type: types.KeyRegistrationTx, Header: header, KeyregTxnFields: keyreg},
		"asset config": {Type: types.AssetConfigTx, Header: header, AssetConfigTxnFields: types.AssetConfigTxnFields{
			ConfigAsset: 7,
			AssetParams: types.AssetParams{
				Total: math.MaxUint64, Decimals: 6, DefaultFrozen: true, UnitName: "U", AssetName: "A", URL: "u",
				MetadataHash: [32]byte{8}, Manager: testAddrToAddress(5), Reserve: testAddrToAddress(6),
				Freeze: testAddrToAddress(7), Clawback: testAddrToAddress(8),
			},
		}},
		"asset transfer": {Type: types.AssetTransferTx, Header: header, AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset: 7, AssetAmount: math.MaxUint64, AssetSender: testAddrToAddress(9),
			AssetReceiver: testAddrToAddress(10), AssetCloseTo: testAddrToAddress(11),
		}},
		"asset freeze": {Type: types.AssetFreezeTx, Header: header, AssetFreezeTxnFields: types.AssetFreezeTxnFields{
			FreezeAccount: testAddrToAddress(12), FreezeAsset: 7, AssetFrozen: true,
		}},
		"app call": {Type: types.ApplicationCallTx, Header: header, ApplicationFields: types.ApplicationFields{
			ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				ApplicationID: 9, OnCompletion: types.OptInOC, ApplicationArgs: [][]byte{{}, []byte("x")},
				Accounts: []types.Address{testAddrToAddress(13)}, ForeignAssets: []types.AssetIndex{0, 7},
				ForeignApps: []types.AppIndex{11}, BoxReferences: []types.BoxReference{{Name: []byte("b")}, {ForeignAppIdx: 1}},
				LocalStateSchema: types.StateSchema{NumUint: 1}, GlobalStateSchema: types.StateSchema{NumByteSlice: 2},
				ApprovalProgram: []byte{6, 129, 1}, ClearStateProgram: []byte{6, 129, 1}, ExtraProgramPages: 1,
			},
		}},
	}

	eng := &Engine{Core: &Core{WriteMode: true}}
	for name, txn := range txns {
		t.Run(name, func(t *testing.T) {
			filename, err := eng.WriteTransactionJSON(txn, "READBACK")
			if err != nil {
				t.Fatalf("WriteTransactionJSON() error = %v", err)
			}
			parsed, err := algo.ParseTransactionFile(filename)
			if err != nil {
				data, _ := os.ReadFile(filename)
				t.Fatalf("ParseTransactionFile() error = %v\n%s", err, data)
			}
			if len(parsed) != 1 || !bytes.Equal(msgpack.Encode(parsed[0]), msgpack.Encode(txn)) {
				t.Fatalf("read back %+v, want %+v", parsed, txn)
			}
		})
	}
}
