// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/approvalpolicy"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// EvaluateAlwaysReviewRules evaluates policy rules that force operator review
// after hard rejection passes and before policy auto-approval. User Auto-Approve
// satisfies these review requirements without an operator prompt.
// A signer-controlled position whose policy cannot be resolved forces review,
// which is the closed outcome this phase can produce.
func EvaluateAlwaysReviewRules(txns []types.Transaction, requestCount int, passthroughIndices, foreignIndices map[int]bool, policyFor PolicyResolver, authKeys []string, knownAddresses map[string]bool, routingExemptIndices map[int]bool) (ruleID string, review bool) {
	return evaluateAlwaysReviewRules(txns, requestCount, passthroughIndices, foreignIndices, policyFor, authKeys, approvalpolicy.Context{KnownAddresses: knownAddresses}, routingExemptIndices)
}

// evaluateAlwaysReviewRules is EvaluateAlwaysReviewRules with a full warning
// context: a rekey the signer issued itself (ProtocolRekeyTargets) is not a
// warning-level finding on any leg.
func evaluateAlwaysReviewRules(txns []types.Transaction, requestCount int, passthroughIndices, foreignIndices map[int]bool, policyFor PolicyResolver, authKeys []string, warnCtx approvalpolicy.Context, routingExemptIndices map[int]bool) (ruleID string, review bool) {
	limit := requestCount
	if limit > len(txns) {
		limit = len(txns)
	}
	for i := 0; i < limit; i++ {
		signerControlled := !passthroughIndices[i] && !foreignIndices[i]
		if signerControlled {
			cfg := resolvePolicy(policyFor, authKeys, i)
			if cfg == nil {
				return "", true
			}
			if violations := policy.CheckTxnReviewPolicyLints(txns[i], cfg); len(violations) > 0 {
				return violations[0].RuleID, true
			}
			if violations := policy.CheckTxnTransferRoutingReviewPolicyLints(txns[i], cfg, routingExemptIndices[i]); len(violations) > 0 {
				return violations[0].RuleID, true
			}
			if cfg.AlwaysReviewWarnings && len(approvalpolicy.CheckDecodedTxnWarningsIn(txns[i], warnCtx)) > 0 {
				return policy.AlwaysReviewWarningsRuleID, true
			}
			continue
		}
		// Passthrough/foreign slot: the signer contributes no signature here, but
		// a group it co-signs that rekeys, closes, clawbacks, or otherwise carries
		// a dangerous field via a passthrough/foreign leg requires review even when
		// AlwaysReviewWarnings is off (it only governs the signer's own legs).
		// User Auto-Approve can satisfy that review without a prompt.
		if len(approvalpolicy.CheckDecodedTxnWarningsIn(txns[i], warnCtx)) > 0 {
			return policy.AlwaysReviewWarningsRuleID, true
		}
	}
	return "", false
}
