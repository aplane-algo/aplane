// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapp/approvalpolicy"

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
	// AuthKeys[i] is the key selector whose policy governs position i ("" or
	// a short slice resolves to the node default).
	AuthKeys             []string
	KnownAddresses       map[string]bool
	RoutingExemptIndices map[int]bool
	// ProtocolRekeyTargets are rekeys the signer issued itself (a rotation's
	// next stage); warning review does not count them.
	ProtocolRekeyTargets map[string]bool
	// ForcedReviewRuleID is a signer-owned unconditional review gate evaluated
	// before policy autoapproval. User Auto-Approve satisfies it without a prompt.
	// It does not depend on policy settings.
	ForcedReviewRuleID string
	// AutoApprove evaluates surface-specific auto-approval rules after review
	// rules pass. Nil means the surface has no auto-approval path.
	AutoApprove func() (ruleID string, approved bool)
	// LogRejection records per-position audit events for a policy rejection.
	LogRejection func(reason string)
	// RequestOperatorApproval blocks on the surface's operator approval prompt.
	// forceReviewRuleID is non-empty when an always-review rule matched.
	RequestOperatorApproval func(ctx context.Context, forceReviewRuleID string) *ServiceError
}

// runApprovalGates runs the shared signer-domain gate sequence: the
// rekey-to-rotating invariant, hard policy rejection, always-review rules, auto-approval rules, then the operator
// approval fallback. It returns the matched
// always-review rule ID for approval audit events ("" when none matched).
func (s *Service) runApprovalGates(ctx context.Context, in gateInput, console Console) (string, *ServiceError) {
	console = consoleOf(console)
	if err := s.rejectRekeyToRotating(in.AllTxns, in.EvalCount, in.PassthroughIndices, in.ForeignIndices); err != nil {
		console.Printf("[SIGNER] Rejected: %s\n", err.Message)
		console.Sync()
		if in.LogRejection != nil {
			in.LogRejection(err.Error())
		}
		return "", err
	}
	if err := EvaluateAutoRejectionRules(in.AllTxns, in.EvalCount, in.PassthroughIndices, in.ForeignIndices, s.policyFor, in.AuthKeys, in.KnownAddresses, in.RoutingExemptIndices, console); err != nil {
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
	alwaysReviewRuleID, alwaysReview := evaluateAlwaysReviewRules(txns, in.EvalCount, in.PassthroughIndices, in.ForeignIndices, s.policyFor, in.AuthKeys, approvalpolicy.Context{KnownAddresses: in.KnownAddresses, ProtocolRekeyTargets: in.ProtocolRekeyTargets}, in.RoutingExemptIndices)
	if in.ForcedReviewRuleID != "" {
		alwaysReviewRuleID = in.ForcedReviewRuleID
		alwaysReview = true
	}

	switch {
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
