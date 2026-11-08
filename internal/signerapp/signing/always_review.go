// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"github.com/aplane-algo/aplane/internal/signerapp/approvalpolicy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// EvaluateAlwaysReviewRules evaluates policy rules that force operator review
// after hard rejection passes and before policy auto-approval. User Auto-Approve
// satisfies these review requirements without an operator prompt.
// A signer-controlled position whose policy cannot be resolved forces review,
// which is the closed outcome this phase can produce. Like
// EvaluateAutoRejectionRules it sees no rekey-to lists; the signer's gates do.
func EvaluateAlwaysReviewRules(txns []types.Transaction, requestCount int, passthroughIndices, foreignIndices map[int]bool, policyFor PolicyResolver, authKeys []string, knownAddresses map[string]bool) (ruleID string, review bool) {
	return evaluateAlwaysReviewRules(txns, requestCount, passthroughIndices, foreignIndices, policyFor, authKeys, approvalpolicy.Context{KnownAddresses: knownAddresses})
}

// evaluateAlwaysReviewRules is EvaluateAlwaysReviewRules with a full warning
// context: a rekey the signer issued itself (ProtocolRekeyTargets) is not a
// warning-level finding on any leg.
func evaluateAlwaysReviewRules(txns []types.Transaction, requestCount int, passthroughIndices, foreignIndices map[int]bool, policyFor PolicyResolver, authKeys []string, warnCtx approvalpolicy.Context) (ruleID string, review bool) {
	return policyeval.ReviewRule(policyeval.Input{
		Group:                txns,
		Slots:                clientSlots(txns, requestCount, passthroughIndices, foreignIndices, policyFor, authKeys, nil),
		KnownAddresses:       warnCtx.KnownAddresses,
		ProtocolRekeyTargets: warnCtx.ProtocolRekeyTargets,
	})
}
