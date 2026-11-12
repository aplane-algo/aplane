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

// DecodePluginDraft reads a plugin's unsigned (raw) transaction intents as the
// draft APlane plans and signs. It is the one reading of a draft: both
// submission paths (through ProcessTransactionIntents) and both client reviews
// decode with it, so a review shows the transactions that are planned.
//
// Each intent must be exactly the canonical encoding of one transaction:
// trailing data such as a second transaction, a repeated field, a fixed-size
// field of the wrong length or an explicit empty field is refused, so the draft
// is what the plugin's bytes say rather than one reading of them.
//
// Any group ID the plugin set is cleared, because the signer computes the
// group ID over the final group, after the fees and dummies it adds.
// groupIDDiscarded reports whether one was, so a review can say so.
func DecodePluginDraft(intents []jsonrpc.TransactionIntent) (txns []types.Transaction, groupIDDiscarded bool, err error) {
	txns = make([]types.Transaction, 0, len(intents))

	for i, intent := range intents {
		if intent.Type != jsonrpc.TransactionIntentRaw {
			return nil, false, fmt.Errorf("transaction %d: unsupported type %q", i+1, intent.Type)
		}
		if intent.Encoded == "" {
			return nil, false, fmt.Errorf("transaction %d: missing encoded data", i+1)
		}

		decoded, err := base64.StdEncoding.DecodeString(intent.Encoded)
		if err != nil {
			return nil, false, fmt.Errorf("transaction %d: failed to decode base64: %w", i+1, err)
		}

		txn, err := canonical.DecodeTxn(decoded)
		if errors.Is(err, canonical.ErrNotCanonical) {
			return nil, false, fmt.Errorf("transaction %d: %w: encoding the decoded transaction again gives different bytes (for example trailing data, a second transaction, a repeated or explicit empty field, a field of the wrong length, or a different key order or integer encoding)", i+1, err)
		}
		if err != nil {
			// The codec's own wording quotes the plugin's bytes, so the user is
			// told only that the msgpack is invalid; a plugin author finds the
			// detail in the debug log, whose handler escapes it.
			var decodeErr *canonical.DecodeError
			if errors.As(err, &decodeErr) {
				logger().Debug("plugin transaction intent is not valid msgpack", "transaction", i+1, "error", decodeErr.Detail)
			}
			return nil, false, fmt.Errorf("transaction %d: failed to decode msgpack: %w", i+1, err)
		}

		if txn.Group != (types.Digest{}) {
			groupIDDiscarded = true
			txn.Group = types.Digest{}
		}
		txns = append(txns, txn)
	}

	return txns, groupIDDiscarded, nil
}

// ProcessTransactionIntents converts plugin transaction intents to the
// unsigned transactions submission plans and signs: the draft DecodePluginDraft
// reads, with any plugin group ID cleared.
func ProcessTransactionIntents(intents []jsonrpc.TransactionIntent) ([]types.Transaction, error) {
	txns, _, err := DecodePluginDraft(intents)
	return txns, err
}
