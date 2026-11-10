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

	if len(data) > 0 && (data[0] == '{' || data[0] == '[') {
		return parseTransactionJSON(data)
	}

	return ParseTransactionBase64(data)
}

func parseTransactionJSON(jsonData []byte) ([]types.Transaction, error) {
	// encoding/json and the SDK's decoder both let a repeated key replace an
	// earlier one, so a file could show one amount and carry another.
	if err := rejectDuplicateJSONKeys(jsonData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	var txnFile struct {
		Transactions []string `json:"txn"`
	}
	if err := json.Unmarshal(jsonData, &txnFile); err == nil && len(txnFile.Transactions) > 0 {
		var txns []types.Transaction
		for i, b64Txn := range txnFile.Transactions {
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

// rejectDuplicateJSONKeys walks one JSON document and refuses a key that
// appears twice in the same object, or anything after the document.
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
			if seen[key] {
				return fmt.Errorf("key %q appears more than once in one object", key)
			}
			seen[key] = true
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
