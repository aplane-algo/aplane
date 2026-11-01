// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"fmt"
	"unicode/utf8"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

// Live policy and ASA set changes. Each request writes a durable intent
// before the change runs, and one outcome entry after it: SUCCEEDED,
// FAILED or COMMIT_UNCERTAIN. The intent records what was asked; the
// outcome what happened, with the evidence the commit captured under the
// store mutation lock. A crash between the two can leave an intent with no
// outcome, which is not proof of failure: the generation records say what
// committed. The request ID correlates the two within a session.
//
// Entries name documents by selector and assets by chain and ID; they never
// carry document contents. Intents are written before the request is
// validated, so every string from a request, and every error text that may
// echo one, is bounded: an entry stays small whatever was sent. Selector
// lists are bounded too, with the number left out.

const (
	// maxAuditSelectors bounds the members of one list in an entry:
	// selectors, generation IDs or archive entries.
	maxAuditSelectors = 64
	// maxAuditField bounds one selector, digest, network, genesis hash or
	// code; real ones are far shorter.
	maxAuditField = 128
	// maxAuditReason bounds an entry's error text.
	maxAuditReason = 1024
)

// boundText cuts s to at most limit bytes at a character boundary, saying
// how long it was.
func boundText(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	note := fmt.Sprintf("…(%d bytes)", len(s))
	cut := max(0, limit-len(note))
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + note
}

// boundList copies at most maxAuditSelectors members of list, each bounded
// to maxAuditField, and returns how many members it left out. It never
// changes list itself.
func boundList(list []string) ([]string, int) {
	if list == nil {
		return nil, 0
	}
	omitted := 0
	if len(list) > maxAuditSelectors {
		list, omitted = list[:maxAuditSelectors], len(list)-maxAuditSelectors
	}
	out := make([]string, len(list))
	for i, k := range list {
		out[i] = boundText(k, maxAuditField)
	}
	return out, omitted
}

// LogPolicyApplyIntentDurableContext records an apply_policy request before
// it runs: the selectors it updates and removes, and the digests it expects,
// which are the request's expectations, not verified state.
func (a *AuditLogger) LogPolicyApplyIntentDurableContext(ctx adminserver.SessionContext, operationID string, req adminproto.ApplyPolicyRequest) error {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditPolicyApplyIntent
	entry.Outcome = "requested"
	entry.OperationID = operationID
	keys := make([]string, 0, len(req.Documents))
	for _, doc := range req.Documents {
		keys = append(keys, doc.Key)
	}
	entry.PolicyUpdates, entry.PolicyUpdatesOmitted = boundList(keys)
	entry.PolicyRemovals, entry.PolicyRemovalsOmitted = boundList(req.Remove)
	entry.ExpectedPolicySetSHA256 = boundText(req.ExpectedPolicySetSHA256, maxAuditField)
	entry.ExpectedSnapshotSHA256 = boundText(req.ExpectedSnapshotSHA256, maxAuditField)
	return a.logDurable(entry)
}

// LogPolicyApplyResultContext records what an apply_policy request did.
func (a *AuditLogger) LogPolicyApplyResultContext(ctx adminserver.SessionContext, operationID string, result adminproto.ApplyPolicyResult) {
	entry := sessionAuditFields(ctx)
	entry.OperationID = operationID
	entry.GenerationID = result.GenerationID
	entry.BasePolicySetSHA256 = result.BasePolicySetSHA256
	entry.PolicySetSHA256 = result.PolicySetSHA256
	switch {
	case result.Success:
		changed := result.Changed
		entry.Event, entry.Outcome, entry.Changed = AuditPolicyApplySucceeded, "succeeded", &changed
	case result.CommitUncertain:
		entry.Event, entry.Outcome = AuditPolicyApplyUncertain, "commit_uncertain"
	default:
		entry.Event, entry.Outcome = AuditPolicyApplyFailed, "failed"
	}
	if !result.Success {
		entry.ResultCode, entry.Reason = boundText(result.Code, maxAuditField), boundText(result.Error, maxAuditReason)
	}
	a.Log(entry)
}

// LogASASetUpdateIntentDurableContext records an add_asa or remove_asa
// request before it runs, with the network, genesis hash and asset the
// request names; the chain is resolved later, under the store lock.
func (a *AuditLogger) LogASASetUpdateIntentDurableContext(ctx adminserver.SessionContext, operationID, action, network, genesisHash string, assetID uint64) error {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditASASetUpdateIntent
	entry.Outcome = "requested"
	entry.OperationID = operationID
	entry.ASAAction = action
	entry.Network, entry.GenesisHash, entry.AssetID = boundText(network, maxAuditField), boundText(genesisHash, maxAuditField), assetID
	return a.logDurable(entry)
}

// LogASASetAddResultContext records what an add_asa request did.
func (a *AuditLogger) LogASASetAddResultContext(ctx adminserver.SessionContext, operationID string, req adminproto.AddASARequest, result adminproto.AddASAResult) {
	network, genesis, assetID := req.Confirmed.Network, req.Confirmed.GenesisHash, req.Confirmed.AssetID
	if result.Success {
		network, genesis, assetID = result.Asset.Network, result.Asset.GenesisHash, result.Asset.AssetID
	}
	a.logASAResult(ctx, operationID, "add", network, genesis, assetID, result.Success, result.CommitUncertain, result.GenerationID, result.Code, result.Error)
}

// LogASASetRemoveResultContext records what a remove_asa request did, with
// the chain the entry was resolved to.
func (a *AuditLogger) LogASASetRemoveResultContext(ctx adminserver.SessionContext, operationID string, req adminproto.RemoveASARequest, result adminproto.RemoveASAResult) {
	genesis := result.GenesisHash
	if genesis == "" {
		genesis = req.GenesisHash
	}
	a.logASAResult(ctx, operationID, "remove", req.Network, genesis, req.AssetID, result.Success, result.CommitUncertain, result.GenerationID, result.Code, result.Error)
}

func (a *AuditLogger) logASAResult(ctx adminserver.SessionContext, operationID, action, network, genesis string, assetID uint64, success, uncertain bool, generationID, code, reason string) {
	entry := sessionAuditFields(ctx)
	entry.OperationID = operationID
	entry.ASAAction = action
	entry.Network, entry.GenesisHash, entry.AssetID = boundText(network, maxAuditField), boundText(genesis, maxAuditField), assetID
	entry.GenerationID = generationID
	switch {
	case success:
		changed := true
		entry.Event, entry.Outcome, entry.Changed = AuditASASetUpdateSucceeded, "succeeded", &changed
	case uncertain:
		entry.Event, entry.Outcome = AuditASASetUpdateUncertain, "commit_uncertain"
	default:
		entry.Event, entry.Outcome = AuditASASetUpdateFailed, "failed"
	}
	if !success {
		entry.ResultCode, entry.Reason = boundText(code, maxAuditField), boundText(reason, maxAuditReason)
	}
	a.Log(entry)
}
