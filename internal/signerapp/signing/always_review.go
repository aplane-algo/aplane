// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/approvalpolicy"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// EvaluateAlwaysReviewRules evaluates policy rules that force operator review
// after hard rejection passes and before auto-approval or the operator default.
func EvaluateAlwaysReviewRules(txns []types.Transaction, requestCount int, passthroughIndices, foreignIndices map[int]bool, policyCfg *policy.Config, authKeys []string, knownAddresses map[string]bool, routingExemptIndices map[int]bool) (ruleID string, review bool) {
	if policyCfg == nil {
		return "", false
	}

	limit := requestCount
	if limit > len(txns) {
		limit = len(txns)
	}
	for i := 0; i < limit; i++ {
		cfg := policyCfg
		signerControlled := !passthroughIndices[i] && !foreignIndices[i]
		if signerControlled && i < len(authKeys) && authKeys[i] != "" {
			cfg = policyCfg.ForKey(authKeys[i])
		}
		if cfg == nil {
			continue
		}
		if signerControlled {
			if violations := policy.CheckTxnReviewPolicyLints(txns[i], cfg); len(violations) > 0 {
				return violations[0].RuleID, true
			}
			if violations := policy.CheckTxnTransferRoutingReviewPolicyLints(txns[i], cfg, routingExemptIndices[i]); len(violations) > 0 {
				return violations[0].RuleID, true
			}
			if cfg.AlwaysReviewWarnings && len(approvalpolicy.CheckDecodedTxnWarnings(txns[i], knownAddresses)) > 0 {
				return policy.AlwaysReviewWarningsRuleID, true
			}
			continue
		}
		// Passthrough/foreign slot: the signer contributes no signature here, but
		// a group it co-signs that rekeys, closes, clawbacks, or otherwise carries
		// a dangerous field via a passthrough/foreign leg must always reach the
		// operator — even under auto-approve and even when AlwaysReviewWarnings is
		// off, which only governs the signer's own legs.
		if len(approvalpolicy.CheckDecodedTxnWarnings(txns[i], knownAddresses)) > 0 {
			return policy.AlwaysReviewWarningsRuleID, true
		}
	}
	return "", false
}
