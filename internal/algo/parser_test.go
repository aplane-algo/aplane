// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package algo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	if !strings.Contains(single, `"amt": 1,`) {
		t.Fatalf("fixture: encoded payment has no amt field: %s", single)
	}
	b64 := base64.StdEncoding.EncodeToString(msgpack.Encode(txn))
	cases := map[string]string{
		"repeated amount":   strings.Replace(single, `"amt": 1,`, `"amt": 1, "amt": 5000000,`, 1),
		"repeated txn list": `{"txn":["` + b64 + `"],"txn":["` + b64 + `"]}`,
		"trailing document": single + single,
		// encoding/json reads "TXN" into the same field as "txn".
		"txn list under two spellings": `{"txn":["` + b64 + `"],"TXN":["` + b64 + `"]}`,
		"repeated key in an array":     "[" + strings.Replace(single, `"amt": 1,`, `"amt": 1, "amt": 2,`, 1) + "]",
	}
	for name, data := range cases {
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

func TestParseTransactionsRefusesWhatADecoderWouldQuietlyDrop(t *testing.T) {
	txn := parserTestPayment(t, 1)
	b64 := base64.StdEncoding.EncodeToString(msgpack.Encode(txn))
	single := string(sdkjson.Encode(txn))

	if txns, err := ParseTransactions([]byte(`{"txn":["` + b64 + `"]}`)); err != nil || len(txns) != 1 {
		t.Fatalf("plain txn list: %d transaction(s), %v", len(txns), err)
	}
	for name, data := range map[string]string{
		"txn list beside another key": `{"txn":["` + b64 + `"],"extra":["` + b64 + `"]}`,
		"txn list beside txns":        `{"txn":["` + b64 + `"],"txns":["` + b64 + `"]}`,
		"txn list spelled TXN":        `{"TXN":["` + b64 + `"]}`,
		"empty txn list":              `{"txn":[]}`,
		"txn list of numbers":         `{"txn":[1]}`,
		"null amount":                 strings.Replace(single, `"amt": 1,`, `"amt": null,`, 1),
		"null in an array":            "[" + single + ", null]",
		"empty map as base64":         "gA==",
		"empty object":                "{}",
	} {
		if txns, err := ParseTransactions([]byte(data)); err == nil {
			t.Errorf("%s: parsed %d transaction(s), want refused", name, len(txns))
		}
	}
}

// parserJSONWith encodes txn as the SDK writes it and replaces or adds the
// given top-level fields with raw JSON.
func parserJSONWith(t *testing.T, txn types.Transaction, fields map[string]string) string {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(string(sdkjson.Encode(txn))))
	decoder.UseNumber()
	var doc map[string]interface{}
	if err := decoder.Decode(&doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	for key, raw := range fields {
		doc[key] = json.RawMessage(raw)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(out)
}

func parserTestKeyreg(t *testing.T) types.Transaction {
	t.Helper()
	txn := parserTestPayment(t, 0)
	txn.Type = types.KeyRegistrationTx
	txn.PaymentTxnFields = types.PaymentTxnFields{}
	for i := range txn.VotePK {
		txn.VotePK[i] = byte(i + 1)
		txn.SelectionPK[i] = byte(i + 101)
	}
	for i := range txn.StateProofPK {
		txn.StateProofPK[i] = byte(i + 7)
	}
	txn.VoteFirst, txn.VoteLast, txn.VoteKeyDilution = 1, 3_000_000, 1733
	return txn
}

func TestParseTransactionsJSONRefusesWhatTheDecoderWouldChange(t *testing.T) {
	b64 := func(n int, first byte) string {
		b := make([]byte, n)
		b[0] = first
		return `"` + base64.StdEncoding.EncodeToString(b) + `"`
	}
	payment := parserTestPayment(t, 1)
	keyreg := parserTestKeyreg(t)
	acfg := parserTestPayment(t, 0)
	acfg.Type = types.AssetConfigTx
	acfg.PaymentTxnFields = types.PaymentTxnFields{}
	acfg.AssetParams.Total = 5

	cases := []struct {
		name string
		data string
		want []string
	}{
		{"31-byte vote key", parserJSONWith(t, keyreg, map[string]string{"votekey": b64(31, 9)}),
			[]string{"transaction 1", `"votekey"`, "holds 31 bytes but the field takes 32"}},
		{"33-byte vote key", parserJSONWith(t, keyreg, map[string]string{"votekey": b64(33, 9)}),
			[]string{"transaction 1", `"votekey"`, "holds 33 bytes"}},
		{"63-byte state proof key", parserJSONWith(t, keyreg, map[string]string{"sprfkey": b64(63, 9)}),
			[]string{`"sprfkey"`, "holds 63 bytes but the field takes 64"}},
		{"31 zero bytes for a vote key", parserJSONWith(t, keyreg, map[string]string{"votekey": `"` + base64.StdEncoding.EncodeToString(make([]byte, 31)) + `"`}),
			[]string{`"votekey"`, "decodes to no value"}},
		{"16-byte metadata hash", parserJSONWith(t, acfg, map[string]string{"apar": `{"am":` + b64(16, 9) + `,"t":5}`}),
			[]string{`"apar.am"`, "holds 16 bytes but the field takes 32"}},
		{"amount with a fraction past 2^53", parserJSONWith(t, payment, map[string]string{"amt": `9007199254740993.0`}),
			[]string{`"amt"`, "9007199254740993.0", "plain digits"}},
		{"amount in exponent form", parserJSONWith(t, payment, map[string]string{"amt": `1e3`}),
			[]string{`"amt"`, "plain digits"}},
		{"zero amount written 0.0", parserJSONWith(t, payment, map[string]string{"amt": `0.0`}),
			[]string{`"amt"`, "decodes to no value"}},
		{"amount as a string", parserJSONWith(t, payment, map[string]string{"amt": `"5"`}),
			[]string{`"amt"`, "is a string in the file but a number"}},
		{"genesis ID as a number", parserJSONWith(t, payment, map[string]string{"gen": `5`}),
			[]string{`"gen"`, "is a number in the file but a string"}},
		{"lease as a short list of numbers", parserJSONWith(t, payment, map[string]string{"lx": `[1,2,3]`}),
			[]string{`"lx"`, "is an array in the file but a string"}},
		{"misspelled amount", parserJSONWith(t, payment, map[string]string{"amnt": `5`}),
			[]string{"amnt"}},
		{"second transaction in an array", "[" + string(sdkjson.Encode(payment)) + "," +
			parserJSONWith(t, keyreg, map[string]string{"votekey": b64(31, 9)}) + "]",
			[]string{"transaction 2", `"votekey"`, "holds 31 bytes"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			txns, err := ParseTransactions([]byte(tc.data))
			if err == nil {
				t.Fatalf("parsed %d transaction(s), want refused: %s", len(txns), tc.data)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestParseTransactionsJSONReadsWhatItStates(t *testing.T) {
	payment := parserTestPayment(t, 18446744073709551615)
	payment.Note = []byte("note")
	payment.Lease = [32]byte{4}
	keyreg := parserTestKeyreg(t)
	two := "[" + string(sdkjson.Encode(payment)) + "," + string(sdkjson.Encode(keyreg)) + "]"

	addresses := parserJSONWith(t, payment, map[string]string{
		"snd": `"` + payment.Sender.String() + `"`,
		"rcv": `"` + payment.Receiver.String() + `"`,
	})
	// Inside an array an entry keeps its place, so the SDK writes an empty
	// one, and it reads back as written.
	appCall := parserTestPayment(t, 0)
	appCall.Type = types.ApplicationCallTx
	appCall.PaymentTxnFields = types.PaymentTxnFields{}
	appCall.ApplicationID = 5
	appCall.ApplicationArgs = [][]byte{{}, []byte("x")}
	appCall.ForeignAssets = []types.AssetIndex{0, 7}
	appCall.Accounts = []types.Address{{}}
	appCall.BoxReferences = []types.BoxReference{{}, {Name: []byte("x")}, {ForeignAppIdx: 1}}
	appCall.Access = []types.ResourceRef{{}, {Holding: types.HoldingRef{Asset: 2}}}
	emptyEntries := string(sdkjson.Encode(appCall))
	for _, entry := range []string{`"apaa": [`, `""`, `"apbx": [`, `{}`, `"al": [`} {
		if !strings.Contains(emptyEntries, entry) {
			t.Fatalf("fixture: SDK encoding has no %s: %s", entry, emptyEntries)
		}
	}

	cases := []struct {
		name string
		data string
		want []types.Transaction
	}{
		{"single transaction", string(sdkjson.Encode(payment)), []types.Transaction{payment}},
		{"array of two", two, []types.Transaction{payment, keyreg}},
		{"keyreg with full-length keys", string(sdkjson.Encode(keyreg)), []types.Transaction{keyreg}},
		{"base32 addresses", addresses, []types.Transaction{payment}},
		{"empty array entries as the SDK writes them", emptyEntries, []types.Transaction{appCall}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			txns, err := ParseTransactions([]byte(tc.data))
			if err != nil {
				t.Fatalf("ParseTransactions() error = %v\n%s", err, tc.data)
			}
			if !bytes.Equal(msgpack.Encode(txns), msgpack.Encode(tc.want)) {
				t.Fatalf("parsed %+v, want %+v", txns, tc.want)
			}
		})
	}
}

func TestParseTransactionsJSONRefusesAFieldTheEncodingLeavesOut(t *testing.T) {
	payment := parserTestPayment(t, 1)
	acfg := parserTestPayment(t, 0)
	acfg.Type = types.AssetConfigTx
	acfg.PaymentTxnFields = types.PaymentTxnFields{}
	acfg.AssetParams.Total = 5
	appCall := parserTestPayment(t, 0)
	appCall.Type = types.ApplicationCallTx
	appCall.PaymentTxnFields = types.PaymentTxnFields{}
	appCall.ApplicationID = 5
	appCall.BoxReferences = []types.BoxReference{{Name: []byte("x")}}
	var zeroAddress types.Address
	zero32 := `"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"`

	cases := []struct {
		name, data, field string
	}{
		{"amount as an empty string", parserJSONWith(t, payment, map[string]string{"amt": `""`}), "amt"},
		{"amount 0", parserJSONWith(t, parserTestPayment(t, 0), map[string]string{"amt": `0`}), "amt"},
		{"fee 0", parserJSONWith(t, payment, map[string]string{"fee": `0`}), "fee"},
		{"empty note", parserJSONWith(t, payment, map[string]string{"note": `""`}), "note"},
		{"note as an object", parserJSONWith(t, payment, map[string]string{"note": `{}`}), "note"},
		{"note as an array", parserJSONWith(t, payment, map[string]string{"note": `[]`}), "note"},
		{"lease as an empty array", parserJSONWith(t, payment, map[string]string{"lx": `[]`}), "lx"},
		{"app args as an object", parserJSONWith(t, payment, map[string]string{"apaa": `{}`}), "apaa"},
		{"boxes as an object", parserJSONWith(t, payment, map[string]string{"apbx": `{}`}), "apbx"},
		{"asset params as an array", parserJSONWith(t, payment, map[string]string{"apar": `[]`}), "apar"},
		{"asset params as an empty object", parserJSONWith(t, payment, map[string]string{"apar": `{}`}), "apar"},
		{"heartbeat as an array", parserJSONWith(t, payment, map[string]string{"hb": `[]`}), "hb"},
		{"nonparticipation false", parserJSONWith(t, payment, map[string]string{"nonpart": `false`}), "nonpart"},
		{"empty genesis ID", parserJSONWith(t, payment, map[string]string{"gen": `""`}), "gen"},
		{"zero close-to address", parserJSONWith(t, payment, map[string]string{"close": `"` + zeroAddress.String() + `"`}), "close"},
		{"all-zero genesis hash", parserJSONWith(t, payment, map[string]string{"gh": zero32}), "gh"},
		{"zero decimals beside a total", parserJSONWith(t, acfg, map[string]string{"apar": `{"t":5,"dc":0}`}), "apar.dc"},
		{"box with app index 0 written out", parserJSONWith(t, appCall, map[string]string{"apbx": `[{"i":0,"n":"eA=="}]`}), "apbx[0].i"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			txns, err := ParseTransactions([]byte(tc.data))
			if err == nil {
				t.Fatalf("parsed %d transaction(s), want refused: %s", len(txns), tc.data)
			}
			want := fmt.Sprintf("field %q decodes to no value: leave it out", tc.field)
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not contain %q", err, want)
			}
		})
	}
}

func TestParseTransactionsJSONRefusesTextADecoderWouldReplace(t *testing.T) {
	payment := parserTestPayment(t, 1)
	acfg := parserTestPayment(t, 0)
	acfg.Type = types.AssetConfigTx
	acfg.PaymentTxnFields = types.PaymentTxnFields{}
	acfg.AssetParams.Total = 5
	withParam := func(key, raw string) string {
		return parserJSONWith(t, acfg, map[string]string{"apar": `{"t":5,"` + key + `":"` + raw + `"}`})
	}

	refused := map[string]struct{ data, want string }{
		"invalid byte in an asset name": {withParam("an", "a\xffb"), "not valid UTF-8"},
		"invalid byte in a unit name":   {withParam("un", "\xc3"), "not valid UTF-8"},
		"invalid byte in a URL":         {withParam("au", "http://a/\xed\xa0\x80"), "not valid UTF-8"},
		"invalid byte in a genesis ID": {parserJSONWith(t, payment, map[string]string{"gen": "\"testnet\xfe\""}),
			"not valid UTF-8"},
		"lone high surrogate":       {withParam("an", `a\ud800b`), `\ud800, half of a surrogate pair`},
		"lone low surrogate":        {withParam("an", `a\udc00b`), `\udc00, half of a surrogate pair`},
		"high surrogate at the end": {withParam("an", `a\ud83d`), `\ud83d, half of a surrogate pair`},
		"two high surrogates":       {withParam("an", `\ud83d\ud83d`), `\ud83d, half of a surrogate pair`},
		"lone surrogate in a gen":   {parserJSONWith(t, payment, map[string]string{"gen": `"\uDBFF"`}), `\udbff`},
		"surrogate after an escape": {withParam("an", `\"\ud800`), `\ud800`},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			txns, err := ParseTransactions([]byte(tc.data))
			if err == nil {
				t.Fatalf("parsed %d transaction(s), want refused: %q", len(txns), tc.data)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}

	accepted := map[string]struct{ data, name string }{
		"surrogate pair":                      {withParam("an", `a😀b`), "a\U0001F600b"},
		"literal emoji":                       {withParam("an", "a\U0001F600b"), "a\U0001F600b"},
		"escaped backslash before u":          {withParam("an", `a\\ud800`), `a\ud800`},
		"replacement character written as is": {withParam("an", "a�b"), "a�b"},
	}
	for name, tc := range accepted {
		t.Run(name, func(t *testing.T) {
			txns, err := ParseTransactions([]byte(tc.data))
			if err != nil {
				t.Fatalf("ParseTransactions() error = %v\n%q", err, tc.data)
			}
			if got := txns[0].AssetParams.AssetName; got != tc.name {
				t.Fatalf("asset name = %q, want %q", got, tc.name)
			}
		})
	}
}
