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
	"os"
	"strings"

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

	var txnArray []types.Transaction
	if err := sdkjson.Decode(jsonData, &txnArray); err == nil {
		if len(txnArray) == 0 {
			return nil, fmt.Errorf("empty transaction array")
		}
		return txnArray, nil
	}

	var txn types.Transaction
	if err := sdkjson.Decode(jsonData, &txn); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: not a valid transaction or transaction array: %w", err)
	}

	return []types.Transaction{txn}, nil
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
