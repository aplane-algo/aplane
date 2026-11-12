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

	rekeyTargets := r.rekeyTargetContext()
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

// rekeyTargetContext is what the connected signer's key list says about rekey
// targets: every address the signer holds an aplane key for, and, by address,
// those whose aplane key is not a valid rekey target. The review then says what
// the signer's own prompt says: a rekey to a held address keeps control, unless
// that aplane key is not a valid rekey target, which it warns about. An account
// signable only through its auth address is not held, so a rekey to it warns
// of losing control, as every rekey does when there is no app.
func (r *REPLState) rekeyTargetContext() txnreview.FindingContext {
	if r.App == nil {
		return txnreview.FindingContext{}
	}
	invalid := make(map[string]txnreview.InvalidRekeyTarget)
	for address, target := range r.App.InvalidRekeyTargets() {
		invalid[address] = txnreview.InvalidRekeyTarget{KeyType: target.KeyType, GenericLogicSig: target.GenericLogicSig}
	}
	return txnreview.FindingContext{KnownAddresses: r.App.HeldKeyAddressSet(), InvalidRekeyTargets: invalid}
}

// pluginReviewLines lists what one slot does: the shared description the
// signer's approval prompt is built from, then every finding the signer would
// warn about, marked `!!`, given what ctx says about rekey targets. A
// plugin-signed slot never reaches the signer, so this can be the only review
// it gets; using the signer's own describer and its own warning rules means
// the two reviews say the same thing about the same bytes.
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
// (apsigner signs it). It reads the draft with engine.DecodePluginDraft, the
// one reading the /plan request is built from, so the review shows the
// transactions that are planned; groupIDDiscarded reports a plugin group ID
// that reading cleared. Display-only; the engine performs authoritative
// validation, and apsigner's /sign approval is the authoritative gate for the
// managed slots.
func decodePresignReviewSlots(intents []jsonrpc.TransactionIntent, pluginSigners []jsonrpc.PluginSigner) (slots []pluginReviewSlot, groupIDDiscarded bool, err error) {
	owned := make(map[string]bool, len(pluginSigners))
	for _, ps := range pluginSigners {
		owned[ps.Address] = true
	}
	txns, groupIDDiscarded, err := engine.DecodePluginDraft(intents)
	if err != nil {
		return nil, false, err
	}
	slots = make([]pluginReviewSlot, len(txns))
	for i, txn := range txns {
		role := slotRoleManaged
		if owned[txn.Sender.String()] {
			role = slotRolePluginSigned
		}
		slots[i] = pluginReviewSlot{txn: txn, role: role}
	}
	return slots, groupIDDiscarded, nil
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
// transactions for APlane-managed accounts, read with engine.DecodePluginDraft
// as submission reads them, through the same renderer the group modes use. It
// is information, not a gate: apsigner plans the final group, and its policy
// and approval apply to it. A draft that rekeys an account to a held aplane key
// that is not a valid rekey target is refused before anything is shown, as
// submission refuses it.
func renderDefaultPluginDraft(r *REPLState, intents []jsonrpc.TransactionIntent) error {
	drafts, groupIDDiscarded, err := engine.DecodePluginDraft(intents)
	if err != nil {
		return err
	}
	if err := r.refuseRekeyToInvalidTarget(drafts); err != nil {
		return err
	}
	slots := make([]pluginReviewSlot, len(drafts))
	for i, txn := range drafts {
		slots[i] = pluginReviewSlot{txn: txn, role: slotRoleManaged}
	}
	renderPluginGroupReview(r, defaultDraftTitle, slots)
	renderDiscardedGroupIDNotice(r, groupIDDiscarded)
	return nil
}
