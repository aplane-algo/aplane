// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// Plugin transaction processing: intent decoding.

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

// DecodeRawTransactionIntents decodes a plugin's unsigned (raw) transaction
// intents, keeping each group field as the plugin set it. Each intent must be
// exactly the canonical encoding of one transaction: trailing data such as a
// second transaction, a repeated field, a fixed-size field of the wrong length
// or an explicit empty field is refused, so what is reviewed, planned and
// signed is what the plugin's bytes say rather than one reading of them.
func DecodeRawTransactionIntents(intents []jsonrpc.TransactionIntent) ([]types.Transaction, error) {
	txns := make([]types.Transaction, 0, len(intents))

	for i, intent := range intents {
		if intent.Type != jsonrpc.TransactionIntentRaw {
			return nil, fmt.Errorf("transaction %d: unsupported type %q", i+1, intent.Type)
		}
		if intent.Encoded == "" {
			return nil, fmt.Errorf("transaction %d: missing encoded data", i+1)
		}

		decoded, err := base64.StdEncoding.DecodeString(intent.Encoded)
		if err != nil {
			return nil, fmt.Errorf("transaction %d: failed to decode base64: %w", i+1, err)
		}

		txn, err := canonical.DecodeTxn(decoded)
		if errors.Is(err, canonical.ErrNotCanonical) {
			return nil, fmt.Errorf("transaction %d: %w: encoding the decoded transaction again gives different bytes (for example trailing data, a second transaction, a repeated or explicit empty field, a field of the wrong length, or a different key order or integer encoding)", i+1, err)
		}
		if err != nil {
			return nil, fmt.Errorf("transaction %d: failed to decode msgpack: %w", i+1, err)
		}
		txns = append(txns, txn)
	}

	return txns, nil
}

// ProcessTransactionIntents converts plugin transaction intents to unsigned
// transactions, decoded as DecodeRawTransactionIntents does. Any group ID the
// plugin set is cleared: the signer computes the group ID over the final
// group, after the fees and dummies it adds. The review says when one was
// discarded.
func ProcessTransactionIntents(intents []jsonrpc.TransactionIntent) ([]types.Transaction, error) {
	txns, err := DecodeRawTransactionIntents(intents)
	if err != nil {
		return nil, err
	}
	for i := range txns {
		txns[i].Group = types.Digest{}
	}
	return txns, nil
}
