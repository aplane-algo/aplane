// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Honest review rendering for plugin-built transaction groups. The renderer is
// role-aware (which party signs each slot). What each transaction does is
// described by internal/txnreview, the describer the signer's approval prompt
// uses; a type it does not know is shown with a line saying its fields are
// not shown, never as a harmless transaction.

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/termsafe"
	"github.com/aplane-algo/aplane/internal/txnreview"
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
// slot it shows the role (who signs it) and the type, then the transaction's
// description and every finding the signer would warn about, marked `!!`. It
// summarizes the fees paid by APlane-managed accounts.
func renderPluginGroupReview(r *REPLState, title string, slots []pluginReviewSlot) {
	r.printf("\n%s\n", title)
	if len(slots) > 0 {
		// Base64, the form plugins, SDKs and explorers show a group ID in, so
		// it can be compared with theirs.
		r.printf("Group ID: %s\n", base64.StdEncoding.EncodeToString(slots[0].txn.Group[:]))
	}
	r.printf("%d transaction(s):\n", len(slots))

	held := r.heldAddresses()
	var managedFees uint64
	for i, s := range slots {
		txn := s.txn
		// The type is the plugin's text: escaped, so it can't draw over the
		// lines that follow.
		// The sender and fee are in the description that follows.
		r.printf("  [%d] %-13s %s\n", i+1, s.role, termsafe.Line(txnTypeLabel(txn.Type)))
		for _, line := range pluginReviewLines(txn, held) {
			r.printf("        %s\n", line)
		}
		if s.role == slotRoleManaged {
			managedFees += uint64(txn.Fee)
		}
	}
	if managedFees > 0 {
		r.printf("Fees paid by APlane-managed accounts: %s ALGO\n", asaset.FormatFixed(managedFees, 6))
	}
}

// heldAddresses is the set of addresses the connected signer holds keys for,
// or nil when that is not known. A rekey to one of them keeps control, and
// the review says so, as the signer's own prompt does.
func (r *REPLState) heldAddresses() map[string]bool {
	if r.App == nil {
		return nil
	}
	return r.App.SignableAddressSet()
}

// pluginReviewLines lists what one slot does: the shared description the
// signer's approval prompt is built from, then every finding the signer would
// warn about, marked `!!`. A plugin-signed slot never reaches the signer, so
// this can be the only review it gets; using the signer's own describer and
// its own warning rules means the two reviews say the same thing about the
// same bytes.
//
// The network is named from the transaction's genesis hash, not from its
// genesis ID, which is text the plugin chose.
func pluginReviewLines(txn types.Transaction, held map[string]bool) []string {
	network, _ := apconfig.DefaultGenesisHashNetworkResolver().NetworkForGenesisHashBytes(txn.GenesisHash[:])
	lines := strings.Split(txnreview.Describe(txn, txnreview.View{Network: network}), "\n")
	for _, finding := range txnreview.Findings(txn, txnreview.FindingContext{KnownAddresses: held}) {
		lines = append(lines, fmt.Sprintf("!! %s = %s", finding.Field, finding.Value))
		for _, line := range strings.Split(finding.Message, "\n") {
			lines = append(lines, "   "+strings.TrimSpace(line))
		}
	}
	return lines
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

// decodePresignReviewSlots decodes a presign-plan draft (every slot Type:"raw",
// unsigned) into review slots, tagging each by signing role: a slot whose sender is
// declared in pluginSigners is plugin-signed; every other slot is APlane-managed
// (apsigner signs it). Display-only; the engine performs authoritative validation,
// and apsigner's /sign approval is the authoritative gate for the managed slots.
func decodePresignReviewSlots(intents []jsonrpc.TransactionIntent, pluginSigners []jsonrpc.PluginSigner) ([]pluginReviewSlot, error) {
	owned := make(map[string]bool, len(pluginSigners))
	for _, ps := range pluginSigners {
		owned[ps.Address] = true
	}
	slots := make([]pluginReviewSlot, len(intents))
	for i, intent := range intents {
		if intent.Type != jsonrpc.TransactionIntentRaw {
			return nil, fmt.Errorf("transaction %d: presign-plan slots must be type %q, got %q", i+1, jsonrpc.TransactionIntentRaw, intent.Type)
		}
		raw, err := base64.StdEncoding.DecodeString(intent.Encoded)
		if err != nil {
			return nil, fmt.Errorf("transaction %d: decode base64: %w", i+1, err)
		}
		var txn types.Transaction
		if err := msgpack.Decode(raw, &txn); err != nil {
			return nil, fmt.Errorf("transaction %d: decode raw: %w", i+1, err)
		}
		role := slotRoleManaged
		if owned[txn.Sender.String()] {
			role = slotRolePluginSigned
		}
		slots[i] = pluginReviewSlot{txn: txn, role: role}
	}
	return slots, nil
}
