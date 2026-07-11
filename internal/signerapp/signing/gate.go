// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// gateInput carries the facts the shared approval gate sequence needs. It is
// deliberately independent of the /sign request and plan shapes so ordinary
// group signing and guarded user-component signing evaluate the same gates
// with the same semantics.
type gateInput struct {
	// AllTxns is the full decoded group, including dummy transactions.
	AllTxns []types.Transaction
	// EvalCount bounds candidate positions: gates evaluate AllTxns[:EvalCount].
	EvalCount int
	// PassthroughIndices and ForeignIndices classify positions this signer does
	// not sign. They are skipped by per-position policy and covered by the
	// foreign-slot always-review warnings instead.
	PassthroughIndices map[int]bool
	ForeignIndices     map[int]bool
	IsGroup            bool
	// Simulation skips review and operator approval: the caller guarantees the
	// resulting signatures never leave the signer.
	Simulation bool
	// AuthKeys[i] selects the policy key override for position i ("" or short
	// slice selects the identity-wide config).
	AuthKeys             []string
	KnownAddresses       map[string]bool
	RoutingExemptIndices map[int]bool
	// AutoApprove evaluates surface-specific auto-approval rules after review
	// rules pass. Nil means the surface has no auto-approval path.
	AutoApprove func() (ruleID string, approved bool)
	// LogRejection records per-position audit events for a policy rejection.
	LogRejection func(reason string)
	// RequestOperatorApproval blocks on the surface's operator approval prompt.
	// forceReviewRuleID is non-empty when an always-review rule matched.
	RequestOperatorApproval func(ctx context.Context, forceReviewRuleID string) *ServiceError
}

// runApprovalGates runs the shared signer-domain gate sequence: hard policy
// rejection, always-review rules, simulation auto-approval, auto-approval
// rules, then the operator approval fallback. It returns the matched
// always-review rule ID for approval audit events ("" when none matched).
func (s *Service) runApprovalGates(ctx context.Context, in gateInput, console Console) (string, *ServiceError) {
	console = consoleOf(console)
	if err := EvaluateAutoRejectionRules(in.AllTxns, in.EvalCount, in.PassthroughIndices, in.ForeignIndices, in.IsGroup, s.Policy, in.AuthKeys, in.KnownAddresses, in.RoutingExemptIndices, console); err != nil {
		if in.LogRejection != nil {
			in.LogRejection(err.Error())
		}
		return "", err
	}

	limit := in.EvalCount
	if limit > len(in.AllTxns) {
		limit = len(in.AllTxns)
	}
	txns := in.AllTxns[:limit]
	alwaysReviewRuleID, alwaysReview := EvaluateAlwaysReviewRules(txns, in.EvalCount, in.PassthroughIndices, in.ForeignIndices, s.Policy, in.AuthKeys, in.KnownAddresses, in.RoutingExemptIndices)

	switch {
	case in.Simulation:
		console.Println("[SIMULATE] Auto-approved inside Signer; signed bytes will not be returned")
	case alwaysReview:
		if err := in.RequestOperatorApproval(ctx, alwaysReviewRuleID); err != nil {
			return alwaysReviewRuleID, err
		}
	default:
		if in.AutoApprove != nil {
			if ruleID, approved := in.AutoApprove(); approved {
				console.Printf("[POLICY] Txn auto-approved (%s)\n", ruleID)
				console.Sync()
				return alwaysReviewRuleID, nil
			}
		}
		if err := in.RequestOperatorApproval(ctx, ""); err != nil {
			return alwaysReviewRuleID, err
		}
	}
	console.Sync()
	return alwaysReviewRuleID, nil
}
