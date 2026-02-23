// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package algo

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func ParseTransactionBase64(base64Data []byte) ([]types.Transaction, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(base64Data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	return ParseTransactionMsgpack(decoded)
}

func ParseTransactionMsgpack(msgpackData []byte) ([]types.Transaction, error) {
	var txn types.Transaction
	if err := msgpack.Decode(msgpackData, &txn); err == nil {
		return []types.Transaction{txn}, nil
	}

	var txnArray []types.Transaction
	if err := msgpack.Decode(msgpackData, &txnArray); err != nil {
		return nil, fmt.Errorf("failed to parse msgpack: not a valid transaction or transaction array: %w", err)
	}

	if len(txnArray) == 0 {
		return nil, fmt.Errorf("empty transaction array")
	}

	return txnArray, nil
}
