// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/txnreview"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SignFileRequest captures parsed inputs for the sign command.
type SignFileRequest struct {
	FilePath string
	Wait     bool
}

// SignFile loads, signs, and submits transactions from a file.
func (a *App) SignFile(ctx context.Context, req SignFileRequest) (*SignFileCommandResult, error) {
	txns, err := algo.ParseTransactionFile(req.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse transaction file: %w", err)
	}

	result, err := a.signTransactions(ctx, txns, req.Wait)
	if err != nil {
		return nil, err
	}

	return &SignFileCommandResult{
		FilePath:  req.FilePath,
		TxCount:   len(txns),
		TxIDs:     append([]string(nil), result.TxIDs...),
		Confirmed: result.Confirmed,
		Output:    result.Output,
		Warnings:  append([]Warning(nil), result.Warnings...),
	}, nil
}

// signTransactions signs and submits pre-built transactions.
func (a *App) signTransactions(ctx context.Context, txns []types.Transaction, wait bool) (*GroupSubmitSummary, error) {
	result, err := a.eng.SignAndSubmitTransactions(ctx, txns, wait)
	if err != nil {
		return nil, err
	}
	return newGroupSubmitSummary(
		result.TxIDs,
		result.Confirmed,
		result.Output,
		warningsFromTransactionWriteNotices(result.WriteNotices),
	), nil
}

// PluginGroup is a plugin result decoded for its group mode and checked under
// the rekey rule, frozen at the check: it holds copies of what the review and
// submission read, never the result itself, and keeps the decoded
// transactions as their encoding, decoded afresh for every use, so nothing a
// caller does to a transaction it was given reaches another. CheckPluginGroup
// is its only constructor. The review renders it and SubmitPluginTransactions
// signs or submits it, so both see the same transactions, and neither can
// reach a group that skipped the check. It also holds the step's arg: words,
// resolved at the check for the group's senders.
type PluginGroup struct {
	checked          bool
	mode             string
	requiresApproval bool
	pluginSigners    []jsonrpc.PluginSigner
	encoded          [][]byte // msgpack of each decoded transaction
	groupIDDiscarded bool
	signed           *engine.PregroupedSignedGroup // pregrouped-signed only
	rekeyTargets     txnreview.FindingContext
	lsigArgs         engine.LsigArgs
}

// PluginCheckOptions is what CheckPluginGroup is told about the review that
// follows it.
type PluginCheckOptions struct {
	// Interactive is set when the review can ask the user. A
	// pregrouped-signed group, whose review is its only gate, is refused
	// without one.
	Interactive bool
	// LsigArgs is the command's arg: words, for the first result of a plugin
	// command only. Each target must be a sender in the group.
	LsigArgs cmdspec.LsigArgs
}

// errPregroupedNonInteractive refuses a pregrouped-signed group for a review
// that cannot ask the user.
var errPregroupedNonInteractive = errors.New("pregrouped-signed groups require interactive review and cannot be submitted in non-interactive (auto-confirm) mode")

// Mode is the result's group mode: empty for the default flow.
func (g *PluginGroup) Mode() string { return g.mode }

// RequiresApproval is the plugin's requiresApproval, which decides the default
// flow's client prompt.
func (g *PluginGroup) RequiresApproval() bool { return g.requiresApproval }

// PluginSigners returns the plugin signers the result declared, for
// presign-plan.
func (g *PluginGroup) PluginSigners() []jsonrpc.PluginSigner {
	return clonePluginSigners(g.pluginSigners)
}

// Transactions returns the decoded group, decoded afresh from what the check
// kept: the draft, with any plugin group ID cleared, for the default flow and
// presign-plan, and the signed group's transactions for pregrouped-signed.
func (g *PluginGroup) Transactions() ([]types.Transaction, error) {
	txns := make([]types.Transaction, len(g.encoded))
	for i, raw := range g.encoded {
		if err := msgpack.Decode(raw, &txns[i]); err != nil {
			return nil, fmt.Errorf("internal error: decoding checked plugin transaction %d: %w", i+1, err)
		}
	}
	return txns, nil
}

// GroupIDDiscarded reports that decoding a draft cleared a group ID the plugin
// set.
func (g *PluginGroup) GroupIDDiscarded() bool { return g.groupIDDiscarded }

// RekeyTargets is what the key list the check fetched says of rekey targets,
// for the review's rekey findings: the facts the check judged the group from.
// They are every address the signer holds an aplane key for, and those whose
// aplane key is not a valid rekey target: the facts the review shares with the
// signer's prompt. The signer also knows each account's rekey-to list, which
// the review does not, so a rekey to a listed address the signer does not
// hold reads here as losing control. It is empty for a group with no rekey,
// which has no rekey finding to show. It returns copies.
func (g *PluginGroup) RekeyTargets() txnreview.FindingContext {
	return txnreview.FindingContext{
		KnownAddresses:       maps.Clone(g.rekeyTargets.KnownAddresses),
		InvalidRekeyTargets:  maps.Clone(g.rekeyTargets.InvalidRekeyTargets),
		ProtocolRekeyTargets: maps.Clone(g.rekeyTargets.ProtocolRekeyTargets),
		ListedRekeyTargets:   maps.Clone(g.rekeyTargets.ListedRekeyTargets),
	}
}

// ErrUncheckedPluginGroup refuses a plugin group CheckPluginGroup did not
// produce.
var ErrUncheckedPluginGroup = errors.New("internal error: the plugin group was not produced by CheckPluginGroup")

// CheckPluginGroup decodes a plugin result for its group mode and applies the
// rekey rule. It is the one decode of a plugin result: the review and
// submission both use the group it returns. A result with localSigners, or
// with a mode it does not know, is refused before anything is decoded. A
// pregrouped-signed group for a review that cannot ask the user is refused
// once decoded, before any key list is fetched: it could never be submitted.
// So is a group the step's arg: words cannot be given to: a pregrouped-signed
// group with any (the plugin signs every transaction), a target that is not
// one of the group's senders or that repeats a name (resolveLsigArgs), and a
// presign-plan group in which an argument reaches a slot the plugin signs
// (refusePluginSignedLsigArgs).
//
// A group in which any transaction rekeys an account is judged against the key
// list fetched from the signer for this check (judgeRekeys), and is refused
// when that list cannot be had, or when a transaction, at any position and
// whoever signs it, rekeys an account to an address the signer holds an
// aplane key for that is not a valid rekey target, the account's own address
// included. That is the rule the signer applies at every position of a group
// it signs into (code rekey_target_not_valid); a plugin-signed position may
// never reach the signer, so apshell applies it itself, before the group is
// shown or prompted for, and SubmitPluginTransactions applies it again. A
// foreign target, one the signer holds no aplane key for, is not refused: the
// review warns about it. A group with no rekey needs no key list and no signer
// connection.
func (a *App) CheckPluginGroup(ctx context.Context, result *jsonrpc.ExecuteResult, opts PluginCheckOptions) (*PluginGroup, error) {
	if result == nil {
		return nil, fmt.Errorf("plugin returned no result")
	}
	if len(result.LocalSigners) > 0 {
		return nil, fmt.Errorf("plugin localSigners are not supported; use groupMode %q or %q",
			jsonrpc.GroupModePresignPlan, jsonrpc.GroupModePregroupedSigned)
	}
	group := &PluginGroup{
		mode:             result.GroupMode,
		requiresApproval: result.RequiresApproval,
		pluginSigners:    clonePluginSigners(result.PluginSigners),
	}
	var txns []types.Transaction
	var err error
	switch result.GroupMode {
	case "":
		txns, group.groupIDDiscarded, err = engine.DecodePluginDraft(result.Transactions)
	case jsonrpc.GroupModePregroupedSigned:
		txns, group.signed, err = decodePregroupedSigned(result.Transactions)
		if err == nil && !opts.Interactive {
			err = errPregroupedNonInteractive
		}
	case jsonrpc.GroupModePresignPlan:
		txns, group.groupIDDiscarded, err = engine.DecodePluginDraft(result.Transactions)
		if err != nil {
			err = fmt.Errorf("presign-plan: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported plugin groupMode %q", result.GroupMode)
	}
	if err != nil {
		return nil, err
	}
	if len(opts.LsigArgs) > 0 {
		if result.GroupMode == jsonrpc.GroupModePregroupedSigned {
			return nil, fmt.Errorf("groupMode %q does not allow LogicSig arguments: the plugin signs every transaction; run the command without its arg: words", jsonrpc.GroupModePregroupedSigned)
		}
		if group.lsigArgs, err = a.resolveLsigArgs(opts.LsigArgs, groupSenders(txns)); err != nil {
			return nil, err
		}
		if result.GroupMode == jsonrpc.GroupModePresignPlan {
			if err := refusePluginSignedLsigArgs(txns, group.lsigArgs, group.pluginSigners); err != nil {
				return nil, err
			}
		}
	}
	group.encoded = make([][]byte, len(txns))
	for i, txn := range txns {
		group.encoded[i] = msgpack.Encode(txn)
	}
	if group.rekeyTargets, err = a.judgeRekeys(ctx, txns); err != nil {
		return nil, err
	}
	group.checked = true
	return group, nil
}

// decodePregroupedSigned decodes a pregrouped-signed result: every intent
// signed, and the group self-consistent (engine.DecodePregroupedSigned). It
// returns the group's transactions and the validated group.
func decodePregroupedSigned(intents []jsonrpc.TransactionIntent) ([]types.Transaction, *engine.PregroupedSignedGroup, error) {
	if len(intents) == 0 {
		return nil, nil, fmt.Errorf("groupMode %q requires transactions", jsonrpc.GroupModePregroupedSigned)
	}
	encoded := make([]string, len(intents))
	for i, intent := range intents {
		if intent.Type != jsonrpc.TransactionIntentSigned {
			return nil, nil, fmt.Errorf("groupMode %q requires every transaction to be type %q; transaction %d is %q",
				jsonrpc.GroupModePregroupedSigned, jsonrpc.TransactionIntentSigned, i+1, intent.Type)
		}
		encoded[i] = intent.Encoded
	}
	signed, err := engine.DecodePregroupedSigned(encoded)
	if err != nil {
		// Some of the engine's errors name the mode already.
		if !strings.HasPrefix(err.Error(), jsonrpc.GroupModePregroupedSigned+": ") {
			err = fmt.Errorf("%s: %w", jsonrpc.GroupModePregroupedSigned, err)
		}
		return nil, nil, err
	}
	stxns := signed.Transactions()
	txns := make([]types.Transaction, len(stxns))
	for i, st := range stxns {
		txns[i] = st.Txn
	}
	return txns, signed, nil
}

// firstRekey is the position of the first transaction with a non-zero
// RekeyTo, or -1 when none has one.
func firstRekey(txns []types.Transaction) int {
	for i, txn := range txns {
		if !txn.RekeyTo.IsZero() {
			return i
		}
	}
	return -1
}

// judgeRekeys applies the rekey rule to a decoded group against the signer's
// key list fetched now (engine.CurrentKeys), which writes no cache, and
// returns the facts it judged from (engine.RekeyTargetsFromKeys), built from
// the records that fetch returned and never from the signer cache. A group
// with no rekey fetches nothing and returns no facts. Without a current list
// the group is refused, since a held aplane key would otherwise read as
// foreign.
func (a *App) judgeRekeys(ctx context.Context, txns []types.Transaction) (txnreview.FindingContext, error) {
	first := firstRekey(txns)
	if first < 0 {
		return txnreview.FindingContext{}, nil
	}
	rekeys := fmt.Sprintf("plugin group rekeys an account (transaction %d)", first+1)
	connectHint := fmt.Errorf("%s: connect to the signer so apshell can check the rekey target against its aplane keys", rekeys)
	if a == nil || a.eng == nil {
		return txnreview.FindingContext{}, connectHint
	}
	keys, err := a.eng.CurrentKeys(ctx)
	switch {
	case errors.Is(err, engine.ErrNotConnected):
		return txnreview.FindingContext{}, connectHint
	case errors.Is(err, engine.ErrSignerLocked):
		return txnreview.FindingContext{}, fmt.Errorf("%s: the signer is locked; unlock it so apshell can check the rekey target against its aplane keys", rekeys)
	case err != nil:
		return txnreview.FindingContext{}, fmt.Errorf("%s: apshell could not get the signer's aplane keys to check the rekey target: %w", rekeys, err)
	}
	targets := engine.RekeyTargetsFromKeys(keys)
	// The signer's rule and the core of its refusal text, naming the position
	// from 1, as the review's slots and the plugin's decode errors do.
	if i, target, found, ok := txnreview.FirstRekeyToInvalidTarget(txns, targets.InvalidRekeyTargets); ok {
		return txnreview.FindingContext{}, fmt.Errorf("transaction %d: %s", i+1, txnreview.RekeyTargetNotValidText(target, found.KeyType))
	}
	return targets, nil
}

// groupSenders is the distinct senders of txns, in order: the accounts a
// plugin group sends from.
func groupSenders(txns []types.Transaction) []string {
	seen := make(map[string]bool, len(txns))
	senders := make([]string, 0, len(txns))
	for _, txn := range txns {
		if sender := txn.Sender.String(); !seen[sender] {
			seen[sender] = true
			senders = append(senders, sender)
		}
	}
	return senders
}

func clonePluginSigners(signers []jsonrpc.PluginSigner) []jsonrpc.PluginSigner {
	if signers == nil {
		return nil
	}
	out := make([]jsonrpc.PluginSigner, len(signers))
	for i, ps := range signers {
		out[i] = ps
		if ps.LsigResources != nil {
			resources := *ps.LsigResources
			out[i].LsigResources = &resources
		}
	}
	return out
}

// SubmitPluginTransactions signs and submits a checked plugin group through
// its mode's path. The group comes from CheckPluginGroup, which the review
// calls first, so the group submitted is the group reviewed. A group with a
// rekey is judged again, against a key list fetched again (judgeRekeys),
// since a key can be created on the signer while the user reviews the group:
// in the default flow before the group goes to the signer, which then applies
// the same rule at every position; for pregrouped-signed before it is
// broadcast; for presign-plan at the start of submission, before planning,
// the plugin's signing and the signer's approval. The LogicSig arguments are
// those the check resolved, each transaction getting its sender's.
func (a *App) SubmitPluginTransactions(ctx context.Context, pluginName string, group *PluginGroup) (*GroupSubmitSummary, error) {
	if group == nil || !group.checked {
		return nil, ErrUncheckedPluginGroup
	}
	switch group.mode {
	case "":
		return a.submitDefaultDraft(ctx, group)
	case jsonrpc.GroupModePregroupedSigned:
		return a.submitPregroupedSigned(ctx, group)
	case jsonrpc.GroupModePresignPlan:
		return a.submitPresignPlan(ctx, pluginName, group)
	default:
		return nil, ErrUncheckedPluginGroup
	}
}

// submitDefaultDraft signs the default flow's draft, APlane-managed slots
// only, through apsigner and submits it.
func (a *App) submitDefaultDraft(ctx context.Context, group *PluginGroup) (*GroupSubmitSummary, error) {
	if !a.eng.IsConnected() {
		return nil, fmt.Errorf("not connected to signer")
	}
	txns, err := group.Transactions()
	if err != nil {
		return nil, err
	}
	// Before the group goes to the signer, which applies the same rule.
	if _, err := a.judgeRekeys(ctx, txns); err != nil {
		return nil, err
	}

	submit, err := a.eng.SignAndSubmitGroup(ctx, txns, group.lsigArgs)
	if err != nil {
		if submit != nil {
			return newGroupSubmitSummary(
				submit.TxIDs,
				submit.Confirmed,
				submit.Output,
				warningsFromTransactionWriteNotices(submit.WriteNotices),
			), err
		}
		return nil, err
	}
	return newGroupSubmitSummary(
		submit.TxIDs,
		submit.Confirmed,
		submit.Output,
		warningsFromTransactionWriteNotices(submit.WriteNotices),
	), nil
}

// submitPregroupedSigned handles a complete, already-signed, already-grouped
// plugin atomic group: CheckPluginGroup validated it is self-consistent, and
// this submits the exact signed bytes verbatim, which the check bound to the
// decoded group (engine.PregroupedSignedGroup). apsigner is not involved, so —
// unlike the other plugin paths — it does NOT require a signer connection, only
// an algod client (checked downstream in SubmitPregroupedSigned), unless the
// group rekeys, which is judged against the signer's key list. It fails closed
// if the result mixes in any APlane-managed signing. It takes no LogicSig
// arguments: CheckPluginGroup refused a group given any.
func (a *App) submitPregroupedSigned(ctx context.Context, group *PluginGroup) (*GroupSubmitSummary, error) {
	txns, err := group.Transactions()
	if err != nil {
		return nil, err
	}
	// Before the group is broadcast.
	if _, err := a.judgeRekeys(ctx, txns); err != nil {
		return nil, err
	}

	confirmed := !a.eng.GetSimulate()
	submit, err := a.eng.SubmitPregroupedSigned(ctx, group.signed)
	if err != nil {
		if submit != nil {
			return newGroupSubmitSummary(submit.TxIDs, confirmed, submit.Output, nil), err
		}
		return nil, err
	}
	return newGroupSubmitSummary(submit.TxIDs, confirmed, submit.Output, nil), nil
}

// submitPresignPlan handles the pre-sign planning flow: the plugin supplies an
// unsigned draft group plus PluginSigners declaring the slots it owns. APlane
// canonicalizes the group (preserving plugin-slot fields), calls back to the plugin
// to sign its slots over the canonical bytes, and submits with apsigner signing the
// managed slots. Requires a signer connection (apsigner signs managed slots).
//
// Review: the CLI renders a role-aware client-side view of the plugin draft
// before this call. The managed slots then go through apsigner /sign, so
// apsigner's policy + approval over the canonical group remains the
// authoritative human-acceptance gate for signer-owned keys.
func (a *App) submitPresignPlan(ctx context.Context, pluginName string, group *PluginGroup) (*GroupSubmitSummary, error) {
	signers := group.pluginSigners
	if len(signers) == 0 {
		return nil, fmt.Errorf("groupMode %q requires pluginSigners", jsonrpc.GroupModePresignPlan)
	}

	refs := make(map[string]string, len(signers))
	authorizations := make(map[string]engine.PluginSlotAuthorization, len(signers))
	for i, ps := range signers {
		if ps.Kind != jsonrpc.PluginSignerKindCallback {
			return nil, fmt.Errorf("pluginSigners[%d]: unsupported kind %q", i, ps.Kind)
		}
		if ps.Address == "" || ps.SignerRef == "" {
			return nil, fmt.Errorf("pluginSigners[%d]: missing address or signerRef", i)
		}
		if _, dup := refs[ps.Address]; dup {
			return nil, fmt.Errorf("pluginSigners[%d]: duplicate address %s", i, ps.Address)
		}
		refs[ps.Address] = ps.SignerRef
		authorization := engine.PluginSlotAuthorization{PQScheme: ps.PQScheme}
		if ps.LsigResources != nil {
			resource := signerapi.LogicSigResourceUsage{
				ProgramBytes:  ps.LsigResources.ProgramBytes,
				ArgumentBytes: ps.LsigResources.ArgumentBytes,
				MaxOpcodeCost: ps.LsigResources.MaxOpcodeCost,
			}
			authorization.LsigResources = &resource
		}
		probe := signerapi.SignRequest{
			TxnBytesHex:   "probe",
			LsigResources: authorization.LsigResources,
			PQScheme:      authorization.PQScheme,
		}
		if err := probe.Validate(); err != nil {
			return nil, fmt.Errorf("pluginSigners[%d]: %w", i, err)
		}
		if authorization.LsigResources != nil || authorization.PQScheme != "" {
			authorizations[ps.Address] = authorization
		}
	}

	// apsigner signs the managed slots, so this flow needs a signer connection.
	if !a.eng.IsConnected() {
		return nil, fmt.Errorf("not connected to signer")
	}
	txns, err := group.Transactions()
	if err != nil {
		return nil, err
	}
	// At the start of submission: before /plan, the plugin's signing callback
	// and the signer's approval wait, none of which apshell judges again.
	if _, err := a.judgeRekeys(ctx, txns); err != nil {
		return nil, err
	}

	signSlots := func(reqs []engine.PluginSlotSignRequest) ([]engine.PluginSlotSigned, error) {
		jr := make([]jsonrpc.SignTransactionRequest, len(reqs))
		for i, r := range reqs {
			jr[i] = jsonrpc.SignTransactionRequest{Index: r.Index, Address: r.Address, SignerRef: r.SignerRef, Encoded: r.Encoded}
		}
		res, err := a.Plugins.SignTransactions(pluginName, jsonrpc.SignTransactionsParams{Requests: jr})
		if err != nil {
			return nil, err
		}
		if res == nil {
			return nil, fmt.Errorf("plugin returned no signing result")
		}
		out := make([]engine.PluginSlotSigned, len(res.Signed))
		for i, s := range res.Signed {
			out[i] = engine.PluginSlotSigned{Index: s.Index, Encoded: s.Encoded}
		}
		return out, nil
	}

	confirmed := !a.eng.GetSimulate()
	submit, err := a.eng.SignAndSubmitWithPluginSigners(ctx, txns, refs, authorizations, signSlots, group.lsigArgs)
	if err != nil {
		if submit != nil {
			return newGroupSubmitSummary(submit.TxIDs, confirmed, submit.Output, nil), err
		}
		return nil, err
	}
	return newGroupSubmitSummary(submit.TxIDs, confirmed, submit.Output, nil), nil
}
