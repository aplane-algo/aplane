// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnutil

import (
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

var txPrefix = [...]byte{'T', 'X'}

// EncodeWithPrefix returns the msgpack transaction bytes with the Algorand
// signing prefix prepended.
func EncodeWithPrefix(txn types.Transaction) []byte {
	encoded := msgpack.Encode(txn)
	result := make([]byte, len(encoded)+len(txPrefix))
	copy(result, txPrefix[:])
	copy(result[len(txPrefix):], encoded)
	return result
}

// EncodeWithPrefixHex returns the TX-prefixed msgpack transaction as hex.
func EncodeWithPrefixHex(txn types.Transaction) string {
	return hex.EncodeToString(EncodeWithPrefix(txn))
}

// DecodePrefixedHex decodes a TX-prefixed hex string into a transaction.
func DecodePrefixedHex(h string) (types.Transaction, error) {
	var txn types.Transaction
	raw, err := hex.DecodeString(h)
	if err != nil {
		return txn, fmt.Errorf("invalid planned txn hex: %w", err)
	}
	if len(raw) < len(txPrefix) || raw[0] != txPrefix[0] || raw[1] != txPrefix[1] {
		return txn, fmt.Errorf("planned transaction missing TX prefix")
	}
	if err := msgpack.Decode(raw[len(txPrefix):], &txn); err != nil {
		return txn, fmt.Errorf("failed to decode planned transaction: %w", err)
	}
	return txn, nil
}
