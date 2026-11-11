// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Honest review rendering for plugin-built transaction groups. The renderer is
// role-aware (which party signs each slot) and marks anything APlane cannot
// decode as opaque rather than rendering it as a harmless transaction.

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/termsafe"
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
// slot it shows the role (who signs it), sender, type, fee, and what the
// transaction does, including every rekey, close and clawback. Anything
// APlane cannot interpret is marked opaque rather than shown as a harmless
// transaction. It summarizes the fees paid by APlane-managed accounts.
func renderPluginGroupReview(r *REPLState, title string, slots []pluginReviewSlot) {
	r.printf("\n%s\n", title)
	if len(slots) > 0 {
		r.printf("Group ID: %s\n", base64.StdEncoding.EncodeToString(slots[0].txn.Group[:]))
	}
	r.printf("%d transaction(s):\n", len(slots))

	var managedFees uint64
	for i, s := range slots {
		txn := s.txn
		// The type is the plugin's text: escaped, so it can't draw over the
		// lines that follow.
		r.printf("  [%d] %-13s %-4s sender=%s fee=%d\n", i+1, s.role, termsafe.Line(txnTypeLabel(txn.Type)), txn.Sender.String(), txn.Fee)
		for _, line := range pluginReviewLines(txn) {
			r.printf("        %s\n", line)
		}
		if s.role == slotRoleManaged {
			managedFees += uint64(txn.Fee)
		}
	}
	if managedFees > 0 {
		r.printf("Fees paid by APlane-managed accounts: %d microAlgo\n", managedFees)
	}
}

// pluginReviewLines lists what one slot does, field by field. Anything that
// hands over control or funds (a rekey, a close, a clawback) is always shown
// and marked, whatever the transaction type: for a plugin-signed slot this
// review can be the only one a person sees.
func pluginReviewLines(txn types.Transaction) []string {
	var zero types.Address
	var lines []string
	add := func(format string, args ...interface{}) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}

	switch txn.Type {
	case types.PaymentTx:
		add("pay %d microAlgo -> %s", txn.Amount, txn.Receiver.String())
	case types.AssetTransferTx:
		add("asset %d: transfer %d base unit(s) -> %s", txn.XferAsset, txn.AssetAmount, txn.AssetReceiver.String())
	case types.ApplicationCallTx:
		if txn.ApplicationID == 0 {
			add("appl create (%s)", onCompletionLabel(txn.OnCompletion))
		} else {
			add("appl id=%d (%s)", txn.ApplicationID, onCompletionLabel(txn.OnCompletion))
		}
		add("%d argument(s), contents opaque to APlane", len(txn.ApplicationArgs))
		for i, account := range txn.Accounts {
			add("account[%d]: %s", i, account.String())
		}
		for i, app := range txn.ForeignApps {
			add("app[%d]: %d", i, app)
		}
		for i, asset := range txn.ForeignAssets {
			add("asset[%d]: %d", i, asset)
		}
		for i, box := range txn.BoxReferences {
			add("box[%d]: %s, name %q", i, pluginBoxApp(txn, box.ForeignAppIdx), box.Name)
		}
		for i, ref := range txn.Access {
			add("access[%d]: %s", i, pluginAccessRef(txn, ref))
		}
		if txn.RejectVersion != 0 {
			add("reject version %d (the call fails if the app's version is that or higher)", txn.RejectVersion)
		}
		if len(txn.ApprovalProgram) > 0 || len(txn.ClearStateProgram) > 0 {
			add("!! carries program code: approval %d byte(s), clear %d byte(s), %d extra page(s)",
				len(txn.ApprovalProgram), len(txn.ClearStateProgram), txn.ExtraProgramPages)
		}
		// The state sizes are fixed at creation and mean nothing on an update.
		if txn.ApplicationID == 0 {
			add("state: global %d uint / %d bytes, local %d uint / %d bytes",
				txn.GlobalStateSchema.NumUint, txn.GlobalStateSchema.NumByteSlice,
				txn.LocalStateSchema.NumUint, txn.LocalStateSchema.NumByteSlice)
		}
	case types.KeyRegistrationTx:
		// Offline means no keys at all, the signer's own rule.
		offline := txn.VotePK == (types.VotePK{}) && txn.SelectionPK == (types.VRFPK{})
		switch {
		case offline && txn.Nonparticipation:
			add("!! keyreg: marks the account nonparticipating (cannot be undone)")
		case offline:
			add("keyreg: go offline")
		default:
			add("keyreg: go online, votes valid %d-%d, key dilution %d",
				txn.VoteFirst, txn.VoteLast, txn.VoteKeyDilution)
			add("vote key %s", keyOrNone(txn.VotePK[:]))
			add("selection key %s", keyOrNone(txn.SelectionPK[:]))
			add("state proof key %s", keyOrNone(txn.StateProofPK[:]))
			if txn.VotePK == (types.VotePK{}) || txn.SelectionPK == (types.VRFPK{}) {
				add("!! a key is missing: this is not a complete online registration")
			}
			if txn.Nonparticipation {
				add("!! also marks the account nonparticipating (cannot be undone)")
			}
		}
	case types.AssetConfigTx:
		switch {
		case txn.ConfigAsset == 0:
			params := txn.AssetParams
			add("asset create: total %d, decimals %d, default frozen %t", params.Total, params.Decimals, params.DefaultFrozen)
			// The names are the creator's text, and a look-alike is cheap.
			add("name %q, unit %q, url %q", termsafe.Line(params.AssetName), termsafe.Line(params.UnitName), termsafe.Line(params.URL))
			if params.MetadataHash != ([32]byte{}) {
				add("metadata hash %s", base64.StdEncoding.EncodeToString(params.MetadataHash[:]))
			}
		case txn.AssetParams == (types.AssetParams{}):
			add("!! asset %d: destroy", txn.ConfigAsset)
		default:
			add("!! asset %d: reconfigure (sets who controls the asset; a role set to none is gone for good)", txn.ConfigAsset)
		}
		if txn.ConfigAsset == 0 || txn.AssetParams != (types.AssetParams{}) {
			add("manager=%s reserve=%s freeze=%s clawback=%s",
				roleAddress(txn.AssetParams.Manager), roleAddress(txn.AssetParams.Reserve),
				roleAddress(txn.AssetParams.Freeze), roleAddress(txn.AssetParams.Clawback))
		}
	case types.AssetFreezeTx:
		action := "unfreeze"
		if txn.AssetFrozen {
			action = "freeze"
		}
		add("asset %d: %s the holding of %s", txn.FreezeAsset, action, txn.FreezeAccount.String())
	default:
		add("(type %q: details opaque to APlane)", txnTypeLabel(txn.Type))
	}

	if txn.RekeyTo != zero {
		add("!! REKEY: control of %s passes to %s", txn.Sender.String(), txn.RekeyTo.String())
	}
	if txn.CloseRemainderTo != zero {
		add("!! CLOSE: the sender's whole ALGO balance -> %s", txn.CloseRemainderTo.String())
	}
	if txn.AssetCloseTo != zero {
		add("!! CLOSE: the sender's whole holding of asset %d -> %s", txn.XferAsset, txn.AssetCloseTo.String())
	}
	// The signer's rule: a clawback takes from someone other than the sender.
	if txn.AssetSender != zero && txn.AssetSender != txn.Sender {
		add("!! CLAWBACK: the asset is taken from %s, not from the sender", txn.AssetSender.String())
	}
	if txn.Lease != ([32]byte{}) {
		add("lease %s", base64.StdEncoding.EncodeToString(txn.Lease[:]))
	}
	return lines
}

// calledApp names the app a call addresses. A create has no ID yet.
func calledApp(txn types.Transaction) string {
	if txn.ApplicationID == 0 {
		return "the app being created"
	}
	return fmt.Sprintf("the called app %d", txn.ApplicationID)
}

// pluginBoxApp names the app a legacy box reference belongs to. Its index is
// one-based into the foreign apps, which are listed above from zero; zero is
// the called app.
func pluginBoxApp(txn types.Transaction, index uint64) string {
	if index == 0 {
		return calledApp(txn)
	}
	if index > uint64(len(txn.ForeignApps)) {
		return fmt.Sprintf("?app[%d] (no such entry)", index-1)
	}
	return fmt.Sprintf("app[%d] = %d", index-1, txn.ForeignApps[index-1])
}

// pluginAccessRef renders one access-list entry. Holding, locals and box
// entries point at other entries by a one-based index, shown here as the
// zero-based access[] label and checked: a pointer to a missing entry, or to
// one of the wrong kind, is shown as such. Zero means the sender or the
// called app.
func pluginAccessRef(txn types.Transaction, ref types.ResourceRef) string {
	pointer := func(index uint64, zero, wantKind string, isKind func(types.ResourceRef) bool) string {
		switch {
		case index == 0:
			return zero
		case index > uint64(len(txn.Access)):
			return fmt.Sprintf("?access[%d] (no such entry)", index-1)
		case !isKind(txn.Access[index-1]):
			return fmt.Sprintf("?access[%d] (not %s)", index-1, wantKind)
		}
		return fmt.Sprintf("access[%d]", index-1)
	}
	account := func(r types.ResourceRef) bool { return r.Address != (types.Address{}) }
	asset := func(r types.ResourceRef) bool { return r.Asset != 0 }
	app := func(r types.ResourceRef) bool { return r.App != 0 }

	var parts []string
	if account(ref) {
		parts = append(parts, "account "+ref.Address.String())
	}
	if asset(ref) {
		parts = append(parts, fmt.Sprintf("asset %d", ref.Asset))
	}
	if app(ref) {
		parts = append(parts, fmt.Sprintf("app %d", ref.App))
	}
	if ref.Holding != (types.HoldingRef{}) {
		parts = append(parts, fmt.Sprintf("holding of %s by %s",
			pointer(ref.Holding.Asset, "?(no asset named)", "an asset", asset),
			pointer(ref.Holding.Address, "the sender", "an account", account)))
	}
	if ref.Locals != (types.LocalsRef{}) {
		parts = append(parts, fmt.Sprintf("local state of %s in %s",
			pointer(ref.Locals.Address, "the sender", "an account", account),
			pointer(ref.Locals.App, calledApp(txn), "an app", app)))
	}
	if ref.Box.ForeignAppIdx != 0 || len(ref.Box.Name) > 0 {
		parts = append(parts, fmt.Sprintf("box of %s, name %q",
			pointer(ref.Box.ForeignAppIdx, calledApp(txn), "an app", app), ref.Box.Name))
	}
	switch len(parts) {
	case 0:
		return "(empty entry: adds box read/write budget)"
	case 1:
		return parts[0]
	default:
		return "MALFORMED, more than one kind: " + strings.Join(parts, "; ")
	}
}

// keyOrNone shows a participation key, or says there is none: an all-zero
// key printed in full would read as a real one.
func keyOrNone(key []byte) string {
	for _, b := range key {
		if b != 0 {
			return base64.StdEncoding.EncodeToString(key)
		}
	}
	return "(none)"
}

func roleAddress(address types.Address) string {
	if address == (types.Address{}) {
		return "(none)"
	}
	return address.String()
}

func onCompletionLabel(onCompletion types.OnCompletion) string {
	switch onCompletion {
	case types.NoOpOC:
		return "NoOp"
	case types.OptInOC:
		return "OptIn"
	case types.CloseOutOC:
		return "CloseOut"
	case types.ClearStateOC:
		return "ClearState"
	case types.UpdateApplicationOC:
		return "!! UpdateApplication"
	case types.DeleteApplicationOC:
		return "!! DeleteApplication"
	default:
		return fmt.Sprintf("on-completion %d", uint64(onCompletion))
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
