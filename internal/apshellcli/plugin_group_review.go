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

	"github.com/aplane-algo/aplane/internal/apshellapp"
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
// description and the findings the signer's warning rules give for it, marked
// `!!`, with rekeyTargets as what is known of rekey targets
// (apshellapp.PluginGroup.RekeyTargets). It summarizes the fees paid by
// APlane-managed accounts.
func renderPluginGroupReview(r *REPLState, title string, slots []pluginReviewSlot, rekeyTargets txnreview.FindingContext) {
	r.printf("\n%s\n", title)
	// Only a group that is submitted as it is has its group ID yet: a draft's
	// is assigned when the signer plans it, so none is shown for one.
	if len(slots) > 0 && slots[0].txn.Group != (types.Digest{}) {
		// Base64, the form plugins, SDKs and explorers show a group ID in, so
		// it can be compared with theirs.
		r.printf("Group ID: %s\n", base64.StdEncoding.EncodeToString(slots[0].txn.Group[:]))
	}
	r.printf("%d transaction(s):\n", len(slots))

	var managedFees uint64
	for i, s := range slots {
		txn := s.txn
		// The type is the plugin's text: escaped, so it can't draw over the
		// lines that follow.
		// The sender and fee are in the description that follows.
		r.printf("  [%d] %-13s %s\n", i+1, s.role, termsafe.Line(txnTypeLabel(txn.Type)))
		for _, line := range pluginReviewLines(txn, rekeyTargets) {
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

// pluginReviewLines lists what one slot does: the shared description the
// signer's approval prompt is built from, then the findings the signer's
// warning rules give, marked `!!`, given what ctx says about rekey targets. A
// plugin-signed slot never reaches the signer, so this can be the only review
// it gets. The two reviews use one describer and one set of warning rules, so
// they say the same thing about the same bytes given the same facts. The facts
// shared are the signer's aplane keys and which of them are not valid rekey
// targets; an account's rekey-to list is not among them, so a rekey to a
// listed address the signer does not hold reads here as losing control, where
// the signer's prompt says the account leaves its custody.
//
// The network is named from the transaction's genesis hash, not from its
// genesis ID, which is text the plugin chose.
func pluginReviewLines(txn types.Transaction, ctx txnreview.FindingContext) []string {
	network, _ := apconfig.DefaultGenesisHashNetworkResolver().NetworkForGenesisHashBytes(txn.GenesisHash[:])
	lines := strings.Split(txnreview.Describe(txn, txnreview.View{Network: network}), "\n")
	for _, finding := range txnreview.Findings(txn, ctx) {
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
func renderPregroupedSignedGroup(r *REPLState, group *apshellapp.PluginGroup) {
	txns := group.Transactions()
	slots := make([]pluginReviewSlot, len(txns))
	for i, txn := range txns {
		slots[i] = pluginReviewSlot{txn: txn, role: slotRolePluginSigned}
	}
	renderPluginGroupReview(r, "LOCAL REVIEW — plugin-signed group (apsigner NOT involved; submitted verbatim)", slots, group.RekeyTargets())
}

// presignReviewSlots tags a presign-plan draft's transactions by signing role:
// a slot whose sender is declared in pluginSigners is plugin-signed; every
// other slot is APlane-managed (apsigner signs it). The draft is the one
// apshellapp.CheckPluginGroup decoded with engine.DecodePluginDraft, the
// reading the /plan request is built from, so the review shows the
// transactions that are planned. Display-only; the engine performs
// authoritative validation, and apsigner's /sign approval is the authoritative
// gate for the managed slots.
func presignReviewSlots(txns []types.Transaction, pluginSigners []jsonrpc.PluginSigner) []pluginReviewSlot {
	owned := make(map[string]bool, len(pluginSigners))
	for _, ps := range pluginSigners {
		owned[ps.Address] = true
	}
	slots := make([]pluginReviewSlot, len(txns))
	for i, txn := range txns {
		role := slotRoleManaged
		if owned[txn.Sender.String()] {
			role = slotRolePluginSigned
		}
		slots[i] = pluginReviewSlot{txn: txn, role: role}
	}
	return slots
}

// defaultDraftTitle heads the default mode's review. It promises nothing
// about a display: under auto-approval apsigner shows nothing, so it names
// what applies to the final group instead.
const defaultDraftTitle = "DRAFT: plugin-built transaction(s); apsigner sets the final fees and group ID, and its policy and approval apply to the final group"

// discardedGroupIDNotice follows a draft review whose plugin set a group ID.
const discardedGroupIDNotice = "The plugin set a group ID; it is discarded, and apsigner computes the group ID over the final group."

// renderDiscardedGroupIDNotice says that a draft's plugin group ID was
// discarded, when one was.
func renderDiscardedGroupIDNotice(r *REPLState, discarded bool) {
	if discarded {
		r.println(discardedGroupIDNotice)
	}
}

// renderDefaultPluginDraft renders a default-mode plugin result: unsigned
// transactions for APlane-managed accounts, the draft submission signs
// (apshellapp.CheckPluginGroup decoded it with engine.DecodePluginDraft),
// through the same renderer the group modes use. It is information, not a
// gate: apsigner plans the final group, and its policy and approval apply to
// it.
func renderDefaultPluginDraft(r *REPLState, group *apshellapp.PluginGroup) {
	drafts := group.Transactions()
	slots := make([]pluginReviewSlot, len(drafts))
	for i, txn := range drafts {
		slots[i] = pluginReviewSlot{txn: txn, role: slotRoleManaged}
	}
	renderPluginGroupReview(r, defaultDraftTitle, slots, group.RekeyTargets())
	renderDiscardedGroupIDNotice(r, group.GroupIDDiscarded())
}
