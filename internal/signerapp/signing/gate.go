// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"

	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Audit reason prefixes for a refused sign. A signer invariant is audited
// the same way on both node roles.
const (
	auditSignerInvariant        = "signer_invariant: "
	auditPolicyRejected         = "policy_engine_rejected: "
	auditCosignerPolicyRejected = "cosigner_policy_rejected: "
)

// gateInput carries the facts the shared approval gate sequence needs. It is
// deliberately independent of the /sign request and plan shapes so ordinary
// group signing and cosigned user-component signing evaluate the same gates
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
	AuthKeys       []string
	KnownAddresses map[string]bool
	// ProtocolRekeyTargets are rekeys the signer issued itself (a rotation's
	// next stage); warning review does not count them.
	ProtocolRekeyTargets map[string]bool
	// ListedRekeyTargets is each position's account rekey-to list, by index.
	ListedRekeyTargets map[int]map[string]bool
	// ForcedReviewRuleID is a signer-owned unconditional review gate evaluated
	// before policy autoapproval. User Auto-Approve satisfies it without a prompt.
	// It does not depend on policy settings.
	ForcedReviewRuleID string
	// Plan is what Always Approve reads from the planner. Nil means the
	// surface has no auto-approval path.
	Plan *policyeval.PlanFacts
	// LogRejection records per-position audit events for a rejection. The
	// reason carries its audit prefix (auditSignerInvariant,
	// auditPolicyRejected).
	LogRejection func(reason string)
	// RequestOperatorApproval blocks on the surface's operator approval prompt.
	// forceReviewRuleID is non-empty when an always-review rule matched.
	RequestOperatorApproval func(ctx context.Context, forceReviewRuleID string) *ServiceError
}

// runApprovalGates runs the shared signer-domain gate sequence: the signer
// invariants (no rekey to a rotating account, no rekey to a held aplane key
// whose key type is not a valid rekey target, no nonparticipating keyreg),
// then the policy verdict (policyeval.Evaluate: hard rejection, always-review
// rules, auto-approval rules), then the operator approval fallback. It returns
// the matched always-review rule ID for approval audit events ("" when none
// matched).
func (s *Service) runApprovalGates(ctx context.Context, in gateInput, console Console) (string, *ServiceError) {
	console = consoleOf(console)
	slots := clientSlots(in.AllTxns, in.EvalCount, in.PassthroughIndices, in.ForeignIndices, s.policyFor, in.AuthKeys, in.ListedRekeyTargets)
	if err := s.rejectSignerInvariants(in.AllTxns, signerPositions(slots)); err != nil {
		console.Printf("[SIGNER] Rejected: %s\n", err.Message)
		console.Sync()
		if in.LogRejection != nil {
			in.LogRejection(auditSignerInvariant + err.Message)
		}
		return "", err
	}
	verdict, evalErr := policyeval.Evaluate(policyeval.Input{
		Group:                in.AllTxns,
		Slots:                slots,
		KnownAddresses:       in.KnownAddresses,
		ProtocolRekeyTargets: in.ProtocolRekeyTargets,
		ForcedReviewRuleID:   in.ForcedReviewRuleID,
		Plan:                 in.Plan,
	})
	var rejection *ServiceError
	switch {
	case evalErr != nil:
		// A position with no policy is a server fault, not a rejection.
		rejection = internal(evalErr.Error())
	case verdict.Outcome == policyeval.Reject:
		rejection = policyRejection(verdict.Violations, console)
	}
	if err := rejection; err != nil {
		if in.LogRejection != nil {
			in.LogRejection(auditPolicyRejected + err.Message)
		}
		return "", err
	}

	switch verdict.Outcome {
	case policyeval.Review:
		if err := in.RequestOperatorApproval(ctx, verdict.RuleID); err != nil {
			return verdict.RuleID, err
		}
		console.Sync()
		return verdict.RuleID, nil
	case policyeval.Approve:
		console.Printf("[POLICY] Txn auto-approved (%s)\n", verdict.RuleID)
		console.Sync()
		return "", nil
	default:
		if err := in.RequestOperatorApproval(ctx, ""); err != nil {
			return "", err
		}
	}
	console.Sync()
	return "", nil
}
