// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// Plugin transaction processing: intent decoding and local signer parsing.

import (
	"encoding/base64"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

// ProcessTransactionIntents converts plugin transaction intents to unsigned transactions.
func ProcessTransactionIntents(intents []jsonrpc.TransactionIntent) ([]types.Transaction, error) {
	txns := make([]types.Transaction, 0, len(intents))

	for i, intent := range intents {
		switch intent.Type {
		case "raw":
			if intent.Encoded == "" {
				return nil, fmt.Errorf("transaction %d: missing encoded data", i+1)
			}

			decoded, err := base64.StdEncoding.DecodeString(intent.Encoded)
			if err != nil {
				return nil, fmt.Errorf("transaction %d: failed to decode base64: %w", i+1, err)
			}

			var txn types.Transaction
			if err := msgpack.Decode(decoded, &txn); err != nil {
				return nil, fmt.Errorf("transaction %d: failed to decode msgpack: %w", i+1, err)
			}

			// Clear group ID - will be re-grouped during signing if needed
			txn.Group = types.Digest{}
			txns = append(txns, txn)

		default:
			return nil, fmt.Errorf("transaction %d: unsupported type %s", i+1, intent.Type)
		}
	}

	return txns, nil
}

// ParseExecuteResultLocalSigners extracts canonical top-level local signers.
func ParseExecuteResultLocalSigners(result *jsonrpc.ExecuteResult) ([]LocalSigner, error) {
	if result == nil {
		return nil, nil
	}
	return decodeLocalSignerPayloads(result.LocalSigners)
}

func decodeLocalSignerPayloads(payloads []jsonrpc.LocalSigner) ([]LocalSigner, error) {
	if len(payloads) == 0 {
		return nil, nil
	}
	result := make([]LocalSigner, 0, len(payloads))
	for i, signer := range payloads {
		if signer.Address == "" {
			return nil, fmt.Errorf("localSigners[%d]: missing address", i)
		}
		if signer.SecretKey == "" {
			return nil, fmt.Errorf("localSigners[%d]: missing secretKey", i)
		}

		secretKey, err := base64.StdEncoding.DecodeString(signer.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("localSigners[%d]: failed to decode secretKey: %w", i, err)
		}

		result = append(result, LocalSigner{
			Address:   signer.Address,
			SecretKey: secretKey,
		})
	}
	return result, nil
}
