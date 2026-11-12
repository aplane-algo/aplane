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

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
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
	// Only a group that is submitted as it is has its group ID yet: a draft's
	// is assigned when the signer plans it, so none is shown for one.
	if len(slots) > 0 && slots[0].txn.Group != (types.Digest{}) {
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
// (apsigner signs it). It decodes with engine.ProcessTransactionIntents, the
// function that builds the draft sent to /plan, so the review shows that draft.
// Display-only; the engine performs authoritative validation, and apsigner's
// /sign approval is the authoritative gate for the managed slots.
func decodePresignReviewSlots(intents []jsonrpc.TransactionIntent, pluginSigners []jsonrpc.PluginSigner) ([]pluginReviewSlot, error) {
	owned := make(map[string]bool, len(pluginSigners))
	for _, ps := range pluginSigners {
		owned[ps.Address] = true
	}
	txns, err := engine.ProcessTransactionIntents(intents)
	if err != nil {
		return nil, err
	}
	slots := make([]pluginReviewSlot, len(txns))
	for i, txn := range txns {
		role := slotRoleManaged
		if owned[txn.Sender.String()] {
			role = slotRolePluginSigned
		}
		slots[i] = pluginReviewSlot{txn: txn, role: role}
	}
	return slots, nil
}

// renderDefaultPluginDraft renders a default-mode plugin result: unsigned
// transactions for APlane-managed accounts, decoded as submission decodes
// them, through the same renderer the group modes use. It is information,
// not a gate: apsigner plans the group and its approval shows the final
// transactions. A group ID the plugin set is discarded at submission (the
// signer computes the group ID over the final group), and the review says so.
func renderDefaultPluginDraft(r *REPLState, intents []jsonrpc.TransactionIntent) error {
	drafts, err := engine.DecodeRawTransactionIntents(intents)
	if err != nil {
		return err
	}
	discarded := false
	slots := make([]pluginReviewSlot, len(drafts))
	for i, txn := range drafts {
		if txn.Group != (types.Digest{}) {
			discarded = true
			txn.Group = types.Digest{}
		}
		slots[i] = pluginReviewSlot{txn: txn, role: slotRoleManaged}
	}
	renderPluginGroupReview(r, "DRAFT: plugin-built transaction(s); apsigner sets the final fees and group ID and shows them for approval", slots)
	if discarded {
		r.println("The plugin set a group ID; it is discarded, and apsigner computes the group ID over the final group.")
	}
	return nil
}
