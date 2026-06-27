// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Honest review rendering for plugin-built transaction groups. The renderer is
// role-aware (which party signs each slot) and marks anything APlane cannot
// decode as opaque rather than rendering it as a harmless transaction.

import (
	"encoding/base64"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

// Slot roles for the honest plugin-group review.
const (
	slotRolePluginSigned = "plugin-signed" // signed by the plugin (passthrough)
	slotRoleManaged      = "apsigner"      // APlane-managed; signed by apsigner
)

// pluginReviewSlot is a decoded transaction with its review role.
type pluginReviewSlot struct {
	txn  types.Transaction
	role string
}

// renderPluginGroupReview prints an honest review of a plugin-built group: per
// slot it shows the role (who signs it), sender, type, fee, and the decodable
// fields, marking anything APlane cannot interpret as opaque rather than as a
// harmless transaction. It summarizes the fees paid by APlane-managed accounts.
func renderPluginGroupReview(r *REPLState, title string, slots []pluginReviewSlot) {
	r.printf("\n%s\n", title)
	if len(slots) > 0 {
		r.printf("Group ID: %s\n", base64.StdEncoding.EncodeToString(slots[0].txn.Group[:]))
	}
	r.printf("%d transaction(s):\n", len(slots))

	var managedFees uint64
	for i, s := range slots {
		txn := s.txn
		r.printf("  [%d] %-13s %-4s sender=%s fee=%d\n", i+1, s.role, txnTypeLabel(txn.Type), txn.Sender.String(), txn.Fee)
		switch txn.Type {
		case types.PaymentTx:
			r.printf("        pay %d microAlgo -> %s\n", txn.Amount, txn.Receiver.String())
			if (txn.CloseRemainderTo != types.Address{}) {
				r.printf("        close remainder -> %s\n", txn.CloseRemainderTo.String())
			}
		case types.ApplicationCallTx:
			r.printf("        appl id=%d (args/proof opaque to APlane)\n", txn.ApplicationID)
		default:
			r.printf("        (details opaque to APlane)\n")
		}
		if s.role == slotRoleManaged {
			managedFees += uint64(txn.Fee)
		}
	}
	if managedFees > 0 {
		r.printf("Fees paid by APlane-managed accounts: %d microAlgo\n", managedFees)
	}
}

func txnTypeLabel(t types.TxType) string {
	if t == "" {
		return "unknown"
	}
	return string(t)
}

// renderPregroupedSignedGroup renders an all-plugin-signed group (apsigner not
// involved) through the shared honest renderer.
func renderPregroupedSignedGroup(r *REPLState, stxns []types.SignedTxn) {
	slots := make([]pluginReviewSlot, len(stxns))
	for i, st := range stxns {
		slots[i] = pluginReviewSlot{txn: st.Txn, role: slotRolePluginSigned}
	}
	renderPluginGroupReview(r, "LOCAL REVIEW — plugin-signed group (apsigner NOT involved; submitted verbatim)", slots)
}

// decodeMixedReviewSlots decodes pregrouped-mixed intents into review slots, tagging
// each with its signing role (plugin-signed passthrough vs APlane-managed). It is
// display-only; the engine performs authoritative validation.
func decodeMixedReviewSlots(intents []jsonrpc.TransactionIntent) ([]pluginReviewSlot, error) {
	slots := make([]pluginReviewSlot, len(intents))
	for i, intent := range intents {
		raw, err := base64.StdEncoding.DecodeString(intent.Encoded)
		if err != nil {
			return nil, fmt.Errorf("transaction %d: decode base64: %w", i+1, err)
		}
		switch intent.Type {
		case jsonrpc.TransactionIntentSigned:
			var st types.SignedTxn
			if err := msgpack.Decode(raw, &st); err != nil {
				return nil, fmt.Errorf("transaction %d: decode signed: %w", i+1, err)
			}
			slots[i] = pluginReviewSlot{txn: st.Txn, role: slotRolePluginSigned}
		case jsonrpc.TransactionIntentRaw:
			var txn types.Transaction
			if err := msgpack.Decode(raw, &txn); err != nil {
				return nil, fmt.Errorf("transaction %d: decode raw: %w", i+1, err)
			}
			slots[i] = pluginReviewSlot{txn: txn, role: slotRoleManaged}
		default:
			return nil, fmt.Errorf("transaction %d: unsupported type %q", i+1, intent.Type)
		}
	}
	return slots, nil
}
