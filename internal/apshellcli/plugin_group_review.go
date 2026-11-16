// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Honest review rendering for plugin-built transaction groups. The renderer is
// role-aware (which party signs each slot). What each transaction does is
// described by internal/txnreview, the describer the signer's approval prompt
// uses; a type it does not know is shown with a line saying its fields are
// not shown, never as a harmless transaction. Who authorizes a slot the plugin
// handed over signed is named by txnreview.Authorization, as the signer's
// prompt names a passthrough slot's authorizer.

import (
	"encoding/base64"
	"fmt"
	"math"
	"math/bits"
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
	// signed is the slot's signed transaction when the plugin handed it over
	// signed (pregrouped-signed), and nil for a slot signed after the review.
	signed *types.SignedTxn
}

// heldSenderText marks a plugin-signed slot whose sender the signer holds the
// aplane key for: the signer's own prompt never sees a pregrouped-signed
// group, and shows a presign-plan slot the plugin signs only as passthrough.
// It says only what is so, whoever the envelope names as authorizing the slot.
const heldSenderText = "THIS SIGNER HOLDS THE APLANE KEY FOR THE SENDER; apsigner does not sign this slot"

// heldAuthorizationKeyText marks a plugin-signed slot whose envelope names, in
// its authorization, an address the signer holds the aplane key for.
func heldAuthorizationKeyText(address types.Address) string {
	return "THIS SIGNER HOLDS THE APLANE KEY FOR " + address.String() + ", NAMED IN THIS SLOT'S AUTHORIZATION; apsigner does not sign this slot"
}

// pluginReviewFacts is what the review of a plugin group knows beyond its
// transactions.
type pluginReviewFacts struct {
	// rekeyTargets is what is known of rekey targets
	// (apshellapp.PluginGroup.RekeyTargets).
	rekeyTargets txnreview.FindingContext
	// held is every address apshell knows the signer holds an aplane key for
	// (apshellapp.PluginGroup.HeldAddresses).
	held map[string]bool
}

// reviewFactsOf is what the check found for group, for its review.
func reviewFactsOf(group *apshellapp.PluginGroup) pluginReviewFacts {
	return pluginReviewFacts{
		rekeyTargets: group.RekeyTargets(),
		held:         group.HeldAddresses(),
	}
}

// renderPluginGroupReview prints an honest review of a plugin-built group: per
// slot it shows the role (who signs it) and the type; for a slot handed over
// signed, who its envelope says authorizes it; for a slot the plugin signs,
// a mark for each held aplane key it involves (pluginSlotLines); then the transaction's
// description, its valid rounds, and the findings the signer's warning rules
// give for it, marked `!!`, given what facts says of rekey targets. It
// summarizes the fees paid by APlane-managed accounts.
func renderPluginGroupReview(r *REPLState, title string, slots []pluginReviewSlot, facts pluginReviewFacts) {
	r.printf("\n%s\n", title)
	// Only a group that is submitted as it is has its group ID yet: a draft's
	// is assigned when the signer plans it, so none is shown for one.
	if len(slots) > 0 && slots[0].txn.Group != (types.Digest{}) {
		// Base64, the form plugins, SDKs and explorers show a group ID in, so
		// it can be compared with theirs.
		r.printf("Group ID: %s\n", base64.StdEncoding.EncodeToString(slots[0].txn.Group[:]))
	}
	r.printf("%d transaction(s):\n", len(slots))

	details := make([]txnreview.Details, len(slots))
	for i, s := range slots {
		txn := s.txn
		details[i] = pluginSlotDetails(txn)
		// The type is the plugin's text: escaped, so it can't draw over the
		// lines that follow.
		// The sender and fee are in the description that follows.
		r.printf("  [%d] %-13s %s\n", i+1, s.role, termsafe.Line(txnTypeLabel(txn.Type)))
		for _, line := range append(pluginSlotLines(s, facts.held), pluginReviewLines(txn, facts.rekeyTargets)...) {
			r.printf("        %s\n", line)
		}
	}
	// What the signer's prompt warns of for a request as a whole: two
	// accounts in the group that look alike.
	for _, finding := range txnreview.LookalikeFindings(details) {
		for _, line := range findingLines(finding) {
			r.printf("  %s\n", line)
		}
	}
	if line := managedFeesLine(slots); line != "" {
		r.println(line)
	}
}

// pluginSlotLines is what the review says of a slot before its transaction:
// who authorizes a slot handed over signed, as its envelope claims, and, for a
// slot the plugin signs, two marks, each shown on its own: that the signer
// holds the aplane key for the sender, and, for each other address the
// envelope names in its authorization (txnreview.AuthorizationAddresses: the
// auth address and every multisig subsignature key), that it holds that one's.
// A presign-plan slot is not signed yet, so only its sender can be judged.
func pluginSlotLines(s pluginReviewSlot, held map[string]bool) []string {
	var lines []string
	if s.signed != nil {
		lines = append(lines, "Authorized by: "+txnreview.Authorization(*s.signed))
	}
	if s.role != slotRolePluginSigned {
		return lines
	}
	if held[s.txn.Sender.String()] {
		lines = append(lines, heldSenderText)
	}
	if s.signed != nil {
		for _, address := range txnreview.AuthorizationAddresses(*s.signed) {
			if address != s.txn.Sender && held[address.String()] {
				lines = append(lines, heldAuthorizationKeyText(address))
			}
		}
	}
	return lines
}

// managedFeesLine sums the fees of the APlane-managed slots, or is empty when
// there are none. A sum too large for 64 bits is said to be, never wrapped.
// A group with an APlane-managed slot is always planned by apsigner after the
// review: the default flow's draft goes to /sign (or to the rotating or
// cosigned route, which plan it too), and a presign-plan group to /plan. A
// pregrouped-signed group has no APlane-managed slot. Planning may raise these
// fees, so the line names them as the fees before planning; the raise itself
// is reported in the command's output (the "Fee adjustment", "[PLUGIN] Signer
// raised fees", "[COSIGNED] Signer raised fees" or rotating "Signer raised the
// spend's fee" line), and apsigner's prompt, when it asks, shows the planned
// group.
func managedFeesLine(slots []pluginReviewSlot) string {
	var total uint64
	managed, overflow := false, false
	for _, s := range slots {
		if s.role != slotRoleManaged {
			continue
		}
		managed = true
		var carry uint64
		total, carry = bits.Add64(total, uint64(s.txn.Fee), 0)
		overflow = overflow || carry != 0
	}
	if !managed {
		return ""
	}
	amount := asaset.FormatFixed(total, 6) + " ALGO"
	if overflow {
		amount = "more than " + asaset.FormatFixed(math.MaxUint64, 6) + " ALGO, too large to add up"
	}
	return "Fees paid by APlane-managed accounts before planning: " + amount +
		" (apsigner may raise them when it plans the group; any raise is reported when the command ends)"
}

// pluginReviewLines lists what one slot does: the shared description the
// signer's approval prompt is built from, the rounds it is valid in, which the
// signer's approval clients show for a whole request, then the findings the
// signer's warning rules give, marked `!!`, given what ctx says about rekey
// targets. A
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
	lines := strings.Split(pluginSlotDetails(txn).Text(), "\n")
	lines = append(lines, validRoundsLine(txn))
	for _, finding := range txnreview.Findings(txn, ctx) {
		lines = append(lines, findingLines(finding)...)
	}
	return lines
}

// pluginSlotDetails describes txn as the signer's prompt does, as data: the
// text of a slot is printed from it, and the group's lookalike check reads
// the accounts it names.
func pluginSlotDetails(txn types.Transaction) txnreview.Details {
	network, _ := apconfig.DefaultGenesisHashNetworkResolver().NetworkForGenesisHashBytes(txn.GenesisHash[:])
	return txnreview.Detail(txn, txnreview.View{Network: network})
}

// findingLines is a finding as the review shows it: marked `!!`, then its
// message.
func findingLines(finding txnreview.Finding) []string {
	head := "!! " + finding.Field
	if finding.Value != "" {
		head += " = " + finding.Value
	}
	lines := []string{head}
	for _, line := range strings.Split(finding.Message, "\n") {
		lines = append(lines, "   "+strings.TrimSpace(line))
	}
	return lines
}

// validRoundsLine is the rounds txn is valid in, from its first to its last
// valid round. A window that ends before it begins is said to be empty.
func validRoundsLine(txn types.Transaction) string {
	line := fmt.Sprintf("  Valid rounds: %d - %d", txn.FirstValid, txn.LastValid)
	if txn.LastValid < txn.FirstValid {
		line += " (empty: no round is valid)"
	}
	return line
}

func txnTypeLabel(t types.TxType) string {
	if t == "" {
		return "unknown"
	}
	return string(t)
}

// renderPregroupedSignedGroup renders an all-plugin-signed group (apsigner not
// involved) through the shared honest renderer, each slot with its signed
// transaction, so the review says who authorizes it.
func renderPregroupedSignedGroup(r *REPLState, group *apshellapp.PluginGroup) error {
	stxns, err := group.SignedTransactions()
	if err != nil {
		return err
	}
	// The review is this group's only gate: never show it as empty.
	if len(stxns) == 0 {
		return fmt.Errorf("internal error: the checked pregrouped-signed group has no signed transactions")
	}
	slots := make([]pluginReviewSlot, len(stxns))
	for i := range stxns {
		slots[i] = pluginReviewSlot{txn: stxns[i].Txn, role: slotRolePluginSigned, signed: &stxns[i]}
	}
	renderPluginGroupReview(r, "LOCAL REVIEW — plugin-signed group (apsigner NOT involved; submitted verbatim)", slots, reviewFactsOf(group))
	return nil
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
func renderDefaultPluginDraft(r *REPLState, group *apshellapp.PluginGroup) error {
	drafts, err := group.Transactions()
	if err != nil {
		return err
	}
	slots := make([]pluginReviewSlot, len(drafts))
	for i, txn := range drafts {
		slots[i] = pluginReviewSlot{txn: txn, role: slotRoleManaged}
	}
	renderPluginGroupReview(r, defaultDraftTitle, slots, reviewFactsOf(group))
	renderDiscardedGroupIDNotice(r, group.GroupIDDiscarded())
	return nil
}
