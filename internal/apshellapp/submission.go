// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/txnreview"
	"github.com/aplane-algo/aplane/pkg/signerapi"

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
// the rekey rule (CheckPluginGroup). The review renders it and
// SubmitPluginTransactions signs or submits it, so both see the same decoded
// transactions, and neither can reach a group that skipped the check.
type PluginGroup struct {
	result           *jsonrpc.ExecuteResult
	txns             []types.Transaction
	groupIDDiscarded bool
	signed           *engine.PregroupedSignedGroup // pregrouped-signed only
	rekeyTargets     txnreview.FindingContext
}

// Mode is the result's group mode: empty for the default flow.
func (g *PluginGroup) Mode() string { return g.result.GroupMode }

// Transactions returns the decoded group: the draft, with any plugin group ID
// cleared, for the default flow and presign-plan, and the signed group's
// transactions for pregrouped-signed.
func (g *PluginGroup) Transactions() []types.Transaction {
	return append([]types.Transaction(nil), g.txns...)
}

// GroupIDDiscarded reports that decoding a draft cleared a group ID the plugin
// set.
func (g *PluginGroup) GroupIDDiscarded() bool { return g.groupIDDiscarded }

// RekeyTargets is what the signer's key list, fetched for this check, says of
// rekey targets, for the review's rekey findings: every address the signer
// holds an aplane key for, and those whose aplane key is not a valid rekey
// target. They are the facts the review shares with the signer's prompt; the
// signer also knows each account's rekey-to list, which the review does not,
// so a rekey to a listed address the signer does not hold reads here as losing
// control. It is empty for a group that rekeys nothing.
func (g *PluginGroup) RekeyTargets() txnreview.FindingContext { return g.rekeyTargets }

// CheckPluginGroup decodes a plugin result for its group mode and applies the
// rekey rule. It is the one decode of a plugin result: the review and
// submission both use the group it returns. A mode it does not know is refused
// before anything is decoded.
//
// A group in which any transaction rekeys an account is judged against the key
// list fetched from the signer for this check, and is refused when that list
// cannot be had, or when a transaction, at any position and whoever signs it,
// rekeys an account to an address the signer holds an aplane key for that is
// not a valid rekey target, the account's own address included. That is the
// rule the signer applies at the positions it signs (code
// rekey_target_not_valid); a plugin-signed position never reaches the signer,
// so apshell applies it to every position, before the group is shown, prompted
// for, sent to the signer or submitted. A foreign target, one the signer holds
// no aplane key for, is not refused: the review warns about it. A group with
// no rekey needs no key list and no signer connection.
func (a *App) CheckPluginGroup(ctx context.Context, result *jsonrpc.ExecuteResult) (*PluginGroup, error) {
	if result == nil {
		return nil, fmt.Errorf("plugin returned no result")
	}
	group := &PluginGroup{result: result}
	var err error
	switch result.GroupMode {
	case "":
		group.txns, group.groupIDDiscarded, err = engine.DecodePluginDraft(result.Transactions)
	case jsonrpc.GroupModePregroupedSigned:
		err = group.decodePregroupedSigned()
	case jsonrpc.GroupModePresignPlan:
		group.txns, group.groupIDDiscarded, err = engine.DecodePluginDraft(result.Transactions)
		if err != nil {
			err = fmt.Errorf("presign-plan: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported plugin groupMode %q", result.GroupMode)
	}
	if err != nil {
		return nil, err
	}
	if err := a.checkPluginRekeys(ctx, group); err != nil {
		return nil, err
	}
	return group, nil
}

// decodePregroupedSigned decodes a pregrouped-signed result: every intent
// signed, and the group self-consistent (engine.DecodePregroupedSigned).
func (g *PluginGroup) decodePregroupedSigned() error {
	intents := g.result.Transactions
	if len(intents) == 0 {
		return fmt.Errorf("groupMode %q requires transactions", jsonrpc.GroupModePregroupedSigned)
	}
	encoded := make([]string, len(intents))
	for i, intent := range intents {
		if intent.Type != jsonrpc.TransactionIntentSigned {
			return fmt.Errorf("groupMode %q requires every transaction to be type %q; transaction %d is %q",
				jsonrpc.GroupModePregroupedSigned, jsonrpc.TransactionIntentSigned, i+1, intent.Type)
		}
		encoded[i] = intent.Encoded
	}
	signed, err := engine.DecodePregroupedSigned(encoded)
	if err != nil {
		return fmt.Errorf("pregrouped-signed: %w", err)
	}
	stxns := signed.Transactions()
	g.txns = make([]types.Transaction, len(stxns))
	for i, st := range stxns {
		g.txns[i] = st.Txn
	}
	g.signed = signed
	return nil
}

// checkPluginRekeys applies the rekey rule to a decoded group. A group with no
// rekey is left alone. Otherwise the signer's key list is fetched
// (engine.RefreshKeys) and read once (engine.RekeyTargetContext); without it the
// group is refused, since an empty or stale cache would make a held aplane key
// read as foreign.
func (a *App) checkPluginRekeys(ctx context.Context, group *PluginGroup) error {
	first := -1
	for i, txn := range group.txns {
		if !txn.RekeyTo.IsZero() {
			first = i
			break
		}
	}
	if first < 0 {
		return nil
	}
	rekeys := fmt.Sprintf("plugin group rekeys an account (transaction %d)", first+1)
	if a == nil || a.eng == nil || !a.eng.IsConnected() {
		return fmt.Errorf("%s: connect to the signer so apshell can check the rekey target against its aplane keys", rekeys)
	}
	if _, err := a.eng.RefreshKeys(ctx); err != nil {
		switch {
		case errors.Is(err, engine.ErrNotConnected):
			return fmt.Errorf("%s: connect to the signer so apshell can check the rekey target against its aplane keys", rekeys)
		case errors.Is(err, engine.ErrSignerLocked):
			return fmt.Errorf("%s: the signer is locked; unlock it so apshell can check the rekey target against its aplane keys", rekeys)
		default:
			return fmt.Errorf("%s: apshell could not get the signer's aplane keys to check the rekey target: %w", rekeys, err)
		}
	}
	group.rekeyTargets = a.eng.RekeyTargetContext()
	return refuseRekeyToInvalidTarget(group.txns, group.rekeyTargets.InvalidRekeyTargets)
}

// refuseRekeyToInvalidTarget refuses the first transaction in txns that rekeys
// an account to one of invalid, the held aplane keys that are not valid rekey
// targets. Its message says what the signer's refusal says, and names the
// position from 1, as the review's slots and the plugin's decode errors do.
func refuseRekeyToInvalidTarget(txns []types.Transaction, invalid map[string]txnreview.InvalidRekeyTarget) error {
	for i, txn := range txns {
		if txn.RekeyTo.IsZero() {
			continue
		}
		target := txn.RekeyTo.String()
		found, ok := invalid[target]
		if !ok {
			continue
		}
		keyType := found.KeyType
		if keyType == "" {
			keyType = "unknown"
		}
		return fmt.Errorf("transaction %d: cannot rekey to %s: this signer holds its aplane key (%s), which is not a valid rekey target",
			i+1, target, keyType)
	}
	return nil
}

// SubmitPluginTransactions signs and submits a checked plugin group through
// its mode's path. The group comes from CheckPluginGroup, which the review
// calls first, so the group submitted is the group reviewed and checked.
func (a *App) SubmitPluginTransactions(ctx context.Context, pluginName string, group *PluginGroup, lsigArgs map[string][]byte) (*GroupSubmitSummary, error) {
	if group == nil || group.result == nil {
		return nil, fmt.Errorf("no checked plugin group to submit")
	}
	result := group.result
	if len(result.LocalSigners) > 0 {
		return nil, fmt.Errorf("plugin localSigners are not supported; use groupMode %q or %q",
			jsonrpc.GroupModePresignPlan, jsonrpc.GroupModePregroupedSigned)
	}

	switch result.GroupMode {
	case "":
		// Default unsigned path: APlane-managed slots only.
	case jsonrpc.GroupModePregroupedSigned:
		return a.submitPregroupedSigned(ctx, group, lsigArgs)
	case jsonrpc.GroupModePresignPlan:
		return a.submitPresignPlan(ctx, pluginName, group, lsigArgs)
	default:
		return nil, fmt.Errorf("unsupported plugin groupMode %q", result.GroupMode)
	}

	if !a.eng.IsConnected() {
		return nil, fmt.Errorf("not connected to signer")
	}

	lsigArgsSlice := perTxnLsigArgs(lsigArgs, len(result.Transactions))
	submit, err := a.eng.SignAndSubmitGroup(ctx, group.txns, lsigArgsSlice)
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
// this submits the exact signed bytes verbatim. apsigner is not involved, so —
// unlike the other plugin paths — it does NOT require a signer connection, only
// an algod client (checked downstream in SubmitPregroupedSigned), unless the
// group rekeys, which CheckPluginGroup judges against the signer's key list. It
// fails closed if the result mixes in any APlane-managed signing.
func (a *App) submitPregroupedSigned(ctx context.Context, group *PluginGroup, lsigArgs map[string][]byte) (*GroupSubmitSummary, error) {
	if len(lsigArgs) > 0 {
		return nil, fmt.Errorf("groupMode %q does not allow lsig args", jsonrpc.GroupModePregroupedSigned)
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
func (a *App) submitPresignPlan(ctx context.Context, pluginName string, group *PluginGroup, lsigArgs map[string][]byte) (*GroupSubmitSummary, error) {
	result := group.result
	if len(result.PluginSigners) == 0 {
		return nil, fmt.Errorf("groupMode %q requires pluginSigners", jsonrpc.GroupModePresignPlan)
	}

	refs := make(map[string]string, len(result.PluginSigners))
	authorizations := make(map[string]engine.PluginSlotAuthorization, len(result.PluginSigners))
	for i, ps := range result.PluginSigners {
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

	lsigArgsSlice := perTxnLsigArgs(lsigArgs, len(result.Transactions))
	confirmed := !a.eng.GetSimulate()
	submit, err := a.eng.SignAndSubmitWithPluginSigners(ctx, group.txns, refs, authorizations, signSlots, lsigArgsSlice)
	if err != nil {
		if submit != nil {
			return newGroupSubmitSummary(submit.TxIDs, confirmed, submit.Output, nil), err
		}
		return nil, err
	}
	return newGroupSubmitSummary(submit.TxIDs, confirmed, submit.Output, nil), nil
}

func perTxnLsigArgs(lsigArgs map[string][]byte, count int) []map[string][]byte {
	if len(lsigArgs) == 0 || count == 0 {
		return nil
	}
	perTxn := make([]map[string][]byte, count)
	for i := range perTxn {
		perTxn[i] = lsigArgs
	}
	return perTxn
}
