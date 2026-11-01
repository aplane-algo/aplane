// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
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
// carry document contents. Selector lists are bounded, with the number left
// out.

// maxAuditSelectors bounds the selectors one entry lists.
const maxAuditSelectors = 64

func boundSelectors(keys []string) ([]string, int) {
	if len(keys) <= maxAuditSelectors {
		return append([]string(nil), keys...), 0
	}
	return append([]string(nil), keys[:maxAuditSelectors]...), len(keys) - maxAuditSelectors
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
	entry.PolicyUpdates, entry.PolicyUpdatesOmitted = boundSelectors(keys)
	entry.PolicyRemovals, entry.PolicyRemovalsOmitted = boundSelectors(req.Remove)
	entry.ExpectedPolicySetSHA256 = req.ExpectedPolicySetSHA256
	entry.ExpectedSnapshotSHA256 = req.ExpectedSnapshotSHA256
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
		entry.ResultCode, entry.Reason = result.Code, result.Error
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
	entry.Network, entry.GenesisHash, entry.AssetID = network, genesisHash, assetID
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
	entry.Network, entry.GenesisHash, entry.AssetID = network, genesis, assetID
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
		entry.ResultCode, entry.Reason = code, reason
	}
	a.Log(entry)
}
