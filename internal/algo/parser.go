// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package algo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	sdkjson "github.com/algorand/go-algorand-sdk/v2/encoding/json"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func ParseTransactionFile(filepath string) ([]types.Transaction, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return ParseTransactions(data)
}

// ParseTransactions auto-detects format (JSON or base64 msgpack) and parses
func ParseTransactions(data []byte) ([]types.Transaction, error) {
	data = []byte(strings.TrimSpace(string(data)))

	var txns []types.Transaction
	var err error
	if len(data) > 0 && (data[0] == '{' || data[0] == '[') {
		txns, err = parseTransactionJSON(data)
	} else {
		txns, err = ParseTransactionBase64(data)
	}
	if err != nil {
		return nil, err
	}
	// An empty map decodes, and re-encodes, as a transaction with nothing in
	// it. It is not one.
	for i, txn := range txns {
		if txn.Type == "" {
			return nil, fmt.Errorf("transaction %d has no type", i+1)
		}
	}
	return txns, nil
}

func parseTransactionJSON(jsonData []byte) ([]types.Transaction, error) {
	if err := checkJSONText(jsonData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	// encoding/json and the SDK's decoder both let a repeated key replace an
	// earlier one, so a file could show one amount and carry another.
	if err := rejectDuplicateJSONKeys(jsonData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	wrapped, isWrapper, err := txnListWrapper(jsonData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	if isWrapper {
		if len(wrapped) == 0 {
			return nil, fmt.Errorf("empty transaction array")
		}
		var txns []types.Transaction
		for i, b64Txn := range wrapped {
			decoded, err := base64.StdEncoding.DecodeString(b64Txn)
			if err != nil {
				return nil, fmt.Errorf("transaction %d: failed to decode base64: %w", i+1, err)
			}

			var txn types.Transaction
			if err := msgpack.Decode(decoded, &txn); err != nil {
				return nil, fmt.Errorf("transaction %d: failed to decode msgpack: %w", i+1, err)
			}
			if !bytes.Equal(msgpack.Encode(txn), decoded) {
				return nil, fmt.Errorf("transaction %d: %w", i+1, errNotCanonical)
			}
			txns = append(txns, txn)
		}
		return txns, nil
	}

	var txns []types.Transaction
	if jsonData[0] == '[' {
		if err := sdkjson.Decode(jsonData, &txns); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: not a valid transaction array: %w", err)
		}
		if len(txns) == 0 {
			return nil, fmt.Errorf("empty transaction array")
		}
	} else {
		var txn types.Transaction
		if err := sdkjson.Decode(jsonData, &txn); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: not a valid transaction: %w", err)
		}
		txns = []types.Transaction{txn}
	}
	if err := checkJSONStatesDecoded(jsonData, txns); err != nil {
		return nil, err
	}
	return txns, nil
}

// checkJSONStatesDecoded compares a JSON transaction file, value by value,
// with the SDK's own JSON encoding of the transactions decoded from it. The
// decoder pads or cuts a fixed-size byte field to its size, reads 1e3, 2.0
// and the string "5" as integers and rounds a fraction past 2^53, so a file
// could show one transaction and carry another. A difference is refused.
//
// Only one thing may differ from the encoding: an address may be written in
// base32, as write mode writes it. Base64 must be spelled as the encoding
// spells it, and a field the encoding leaves out, at its zero value, must be
// left out of the file too.
func checkJSONStatesDecoded(jsonData []byte, txns []types.Transaction) error {
	given, err := decodeJSONExactly(jsonData)
	if err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	entries, isArray := given.([]interface{})
	if !isArray {
		entries = []interface{}{given}
	}
	if len(entries) != len(txns) {
		return fmt.Errorf("the file holds %d transaction(s) but %d decoded", len(entries), len(txns))
	}
	for i, txn := range txns {
		// The decoder reads an array into a struct by position.
		if _, isObject := entries[i].(map[string]interface{}); !isObject {
			return fmt.Errorf("transaction %d is %s, not a transaction object", i+1, jsonKind(entries[i]))
		}
		decoded, err := decodeJSONExactly(sdkjson.Encode(txn))
		if err != nil {
			// A state proof with reveals: its map is written with bare keys.
			return fmt.Errorf("transaction %d cannot be read from JSON: the SDK does not write it as valid JSON, so the file cannot be checked against it", i+1)
		}
		if err := sameJSONValue("", entries[i], decoded); err != nil {
			return fmt.Errorf("transaction %d: %w", i+1, err)
		}
	}
	return nil
}

// decodeJSONExactly decodes one JSON document with every number kept as the
// text it was written as.
func decodeJSONExactly(data []byte) (interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

// sameJSONValue reports the first place where a value from the file differs
// from the value the transaction encodes there.
func sameJSONValue(path string, given, decoded interface{}) error {
	switch g := given.(type) {
	case map[string]interface{}:
		d, ok := decoded.(map[string]interface{})
		if !ok {
			return kindMismatch(path, given, decoded)
		}
		for _, key := range slices.Sorted(maps.Keys(g)) {
			field := joinJSONPath(path, key)
			value, present := d[key]
			if !present {
				// The encoding leaves out a field at its zero value, so
				// anything written there, 0 or "" included, is not read as
				// written: "amt": "" would send nothing.
				return fmt.Errorf("field %q decodes to no value: leave it out", field)
			}
			if err := sameJSONValue(field, g[key], value); err != nil {
				return err
			}
		}
		for _, key := range slices.Sorted(maps.Keys(d)) {
			if _, present := g[key]; !present {
				return fmt.Errorf("field %q is in the decoded transaction but not in the file", joinJSONPath(path, key))
			}
		}
		return nil
	case []interface{}:
		d, ok := decoded.([]interface{})
		if !ok {
			return kindMismatch(path, given, decoded)
		}
		if len(g) != len(d) {
			return fmt.Errorf("field %q holds %d entries but decodes to %d", path, len(g), len(d))
		}
		for i := range g {
			if err := sameJSONValue(fmt.Sprintf("%s[%d]", path, i), g[i], d[i]); err != nil {
				return err
			}
		}
		return nil
	case json.Number:
		d, ok := decoded.(json.Number)
		if !ok {
			return kindMismatch(path, given, decoded)
		}
		if strings.Trim(string(g), "0123456789") != "" {
			return fmt.Errorf("field %q is %s: write a whole number in plain digits", path, g)
		}
		if g != d {
			return fmt.Errorf("field %q is %s but decodes to %s", path, g, d)
		}
		return nil
	case string:
		d, ok := decoded.(string)
		if !ok {
			return kindMismatch(path, given, decoded)
		}
		if g == d {
			return nil
		}
		return sameBytes(path, g, d)
	case bool:
		d, ok := decoded.(bool)
		if !ok {
			return kindMismatch(path, given, decoded)
		}
		if g != d {
			return fmt.Errorf("field %q is %t but decodes to %t", path, g, d)
		}
		return nil
	default:
		return fmt.Errorf("field %q has no value", path)
	}
}

// sameBytes is called for a string from the file that differs from the one
// the transaction encodes. Base64 has to be spelled as the encoding spells
// it, since a decoder also takes non-zero trailing bits and line breaks; the
// only other spelling is an address in base32.
func sameBytes(path, given, decoded string) error {
	if want, err := base64.StdEncoding.DecodeString(decoded); err == nil {
		if address, err := types.DecodeAddress(given); err == nil && bytes.Equal(address[:], want) {
			return nil
		}
		if have, err := base64.StdEncoding.Strict().DecodeString(given); err == nil && len(have) != len(want) {
			return fmt.Errorf("field %q holds %d bytes but the field takes %d", path, len(have), len(want))
		}
	}
	return fmt.Errorf("field %q is %q but decodes to %q", path, given, decoded)
}

func joinJSONPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func kindMismatch(path string, given, decoded interface{}) error {
	return fmt.Errorf("field %q is %s in the file but %s in the decoded transaction",
		path, jsonKind(given), jsonKind(decoded))
}

func jsonKind(v interface{}) string {
	switch v.(type) {
	case map[string]interface{}:
		return "an object"
	case []interface{}:
		return "an array"
	case json.Number:
		return "a number"
	case string:
		return "a string"
	case bool:
		return "true or false"
	}
	return "null"
}

// txnListWrapper recognises the `{"txn": [...]}` file form. The object may
// hold that one key and nothing else, spelled exactly: any other key would be
// ignored by a decoder, and a list under another spelling would be dropped or
// taken in place of the one shown.
func txnListWrapper(jsonData []byte) (entries []string, isWrapper bool, err error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(jsonData, &object) != nil {
		return nil, false, nil
	}
	list, ok := object["txn"]
	if !ok {
		for key := range object {
			if strings.EqualFold(key, "txn") {
				return nil, false, fmt.Errorf("key %q must be spelled \"txn\"", key)
			}
		}
		return nil, false, nil
	}
	if len(object) != 1 {
		return nil, false, fmt.Errorf("a \"txn\" list file may hold no other key")
	}
	if err := json.Unmarshal(list, &entries); err != nil {
		return nil, false, fmt.Errorf("\"txn\" must be a list of base64 strings: %w", err)
	}
	return entries, true, nil
}

// checkJSONText refuses text a decoder would replace. The SDK's decoder
// keeps bytes that are not UTF-8, which encoding/json reads as U+FFFD, so an
// asset name could be compared as one text and signed as another; and both
// decoders turn a \u escape for half a surrogate pair into U+FFFD, which is
// not the text the file shows.
func checkJSONText(data []byte) error {
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			return fmt.Errorf("the file is not valid UTF-8 (byte %d)", i)
		}
		i += size
	}
	// A backslash appears only inside a string, where it starts an escape.
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		r, ok := jsonEscapedRune(data, i)
		if !ok || !utf16.IsSurrogate(r) {
			continue
		}
		i += 4
		if low, ok := jsonEscapedRune(data, i+2); ok && data[i+1] == '\\' &&
			utf16.DecodeRune(r, low) != utf8.RuneError {
			i += 6
			continue
		}
		return fmt.Errorf("the file has \\u%04x, half of a surrogate pair, which a decoder reads as U+FFFD", r)
	}
	return nil
}

// jsonEscapedRune reads the code unit of a \uXXXX escape whose u is at i.
func jsonEscapedRune(data []byte, i int) (rune, bool) {
	if i+5 > len(data) || data[i] != 'u' {
		return 0, false
	}
	n, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
	if err != nil {
		return 0, false
	}
	return rune(n), true
}

// rejectDuplicateJSONKeys walks one JSON document and refuses a key that
// appears twice in the same object, a null, or anything after the document.
func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("unexpected data after the JSON document")
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		// A decoder reads null as zero or empty, so `"amt": null` would show
		// no amount and send none where the writer may have meant another.
		return fmt.Errorf("null is not a value in a transaction file")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, _ := keyToken.(string)
			// encoding/json matches field names without regard to case, so
			// "txn" and "TXN" are the same key to it.
			folded := strings.ToLower(key)
			if seen[folded] {
				return fmt.Errorf("key %q appears more than once in one object", key)
			}
			seen[folded] = true
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
	}
	_, err = decoder.Token()
	return err
}

func ParseTransactionBase64(base64Data []byte) ([]types.Transaction, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(base64Data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	return ParseTransactionMsgpack(decoded)
}

var errNotCanonical = errors.New(
	"the bytes are not the canonical encoding of the transaction they decode to " +
		"(a repeated field, an explicit empty field, or a non-standard encoding)")

// ParseTransactionMsgpack reads one transaction, several written one after
// another, or one array of transactions. Every byte has to belong to a
// transaction, and each transaction has to be in canonical form: the decoder
// alone would stop after the first value and let a repeated field win.
func ParseTransactionMsgpack(msgpackData []byte) ([]types.Transaction, error) {
	if len(msgpackData) == 0 {
		return nil, fmt.Errorf("failed to parse msgpack: no data")
	}

	if isMsgpackArray(msgpackData[0]) {
		var txnArray []types.Transaction
		if err := msgpack.Decode(msgpackData, &txnArray); err != nil {
			return nil, fmt.Errorf("failed to parse msgpack: not a valid transaction array: %w", err)
		}
		if len(txnArray) == 0 {
			return nil, fmt.Errorf("empty transaction array")
		}
		if !bytes.Equal(msgpack.Encode(txnArray), msgpackData) {
			return nil, fmt.Errorf("failed to parse msgpack: %w", errNotCanonical)
		}
		return txnArray, nil
	}

	var txns []types.Transaction
	var canonical []byte
	decoder := msgpack.NewDecoder(bytes.NewReader(msgpackData))
	for {
		var txn types.Transaction
		err := decoder.Decode(&txn)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf(
				"failed to parse msgpack: transaction %d is not a valid transaction: %w", len(txns)+1, err)
		}
		txns = append(txns, txn)
		canonical = append(canonical, msgpack.Encode(txn)...)
	}
	if !bytes.Equal(canonical, msgpackData) {
		return nil, fmt.Errorf("failed to parse msgpack: %w", errNotCanonical)
	}
	return txns, nil
}

// isMsgpackArray reports whether a first byte opens a msgpack array.
func isMsgpackArray(first byte) bool {
	return first&0xf0 == 0x90 || first == 0xdc || first == 0xdd
}
