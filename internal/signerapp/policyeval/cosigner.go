// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyeval

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/policy"
)

// cosignerVerdict is the cosigner verdict: Approve when every target passes
// its policy, else Reject with the violations of every target, each at its
// group index. A cosigner has no operator, so a review-producing rule is a
// rejection, and a target on a network the node does not know is a violation
// rather than a refusal before policy.
func cosignerVerdict(in Input) (Verdict, error) {
	for _, slot := range in.Slots {
		if slot.Policy == nil {
			return Verdict{}, ErrPolicyNotLoaded
		}
	}
	// Known-network gate: asset references are only meaningful on a known
	// network; the gate applies to every target, including ones that name no
	// asset (a cosigner rekey is a 0 ALGO self-payment), so no rule has to
	// prove it cannot carry one.
	var violations []policy.LintViolation
	for _, slot := range in.Slots {
		txn := in.Group[slot.Index]
		if _, ok := in.Networks.NetworkForGenesisHashBytes(txn.GenesisHash[:]); !ok {
			violations = append(violations, policy.LintViolation{
				RuleID:   policy.UnknownGenesisHashRuleID,
				Scope:    "txn",
				TxnIndex: slot.Index,
				Message:  fmt.Sprintf("cannot evaluate cosigner policy for unknown genesis hash %x", txn.GenesisHash[:]),
			})
			continue
		}
		violations = append(violations, cosignerTargetLints(txn, slot.Index, slot.Policy)...)
	}
	if len(violations) > 0 {
		return Verdict{Outcome: Reject, Violations: violations}, nil
	}
	return Verdict{Outcome: Approve}, nil
}

// cosignerTargetLints is one target's violations. A transaction-rule
// violation ends the target, and a rekey is judged by the cosigner's rekey
// rules alone; otherwise transfer routing, then the review-producing rules,
// all count as rejections.
func cosignerTargetLints(txn types.Transaction, targetIndex int, cfg *policy.Config) []policy.LintViolation {
	violations := withTargetIndex(policy.CheckTxnPolicyLints(txn, cfg, nil), targetIndex)
	if len(violations) > 0 {
		return violations
	}
	if !txn.RekeyTo.IsZero() {
		if cfg.RejectRekey {
			return []policy.LintViolation{cosignerRekeyViolation(targetIndex, "rekey transactions are rejected by cosigner policy")}
		}
		return cosignerRekeyPolicyLints(txn, targetIndex, cfg)
	}
	if cfg.TransferPolicy == nil {
		// A compiled document always carries a transfer policy. A config
		// without one has no allow-list, so nothing it covers can be signed.
		return []policy.LintViolation{{
			RuleID:   policy.TransferRoutingRouteMissRuleID,
			Scope:    "txn",
			TxnIndex: targetIndex,
			Message:  "cosigner policy has no transfer policy; no route can authorize the target",
		}}
	}
	violations = append(violations, withTargetIndex(
		policy.CheckTxnTransferRoutingPolicyLints(txn, cfg),
		targetIndex,
	)...)
	// Defense in depth: decode refuses review-producing fields on a cosigner
	// node, so these never fire for a stored document, but a review verdict
	// must never be waited on here.
	violations = append(violations, withTargetIndex(
		policy.CheckTxnReviewPolicyLints(txn, cfg),
		targetIndex,
	)...)
	violations = append(violations, withTargetIndex(
		policy.CheckTxnTransferRoutingReviewPolicyLints(txn, cfg),
		targetIndex,
	)...)
	return violations
}

func cosignerRekeyPolicyLints(txn types.Transaction, targetIndex int, cfg *policy.Config) []policy.LintViolation {
	if txn.Type != types.PaymentTx {
		return []policy.LintViolation{cosignerRekeyViolation(targetIndex, "rekey transactions must be payment transactions")}
	}
	if txn.Amount != 0 {
		return []policy.LintViolation{cosignerRekeyViolation(targetIndex, "rekey transactions must transfer 0 microalgos")}
	}
	if txn.Receiver != txn.Sender {
		return []policy.LintViolation{cosignerRekeyViolation(targetIndex, "rekey transactions must be self-payments")}
	}
	if !txn.CloseRemainderTo.IsZero() {
		return []policy.LintViolation{cosignerRekeyViolation(targetIndex, "rekey transactions must not close remainder")}
	}
	if cfg == nil || cfg.RekeyPolicy == nil || !cfg.RekeyPolicy.Allows(txn.Sender, txn.RekeyTo) {
		return []policy.LintViolation{cosignerRekeyViolation(
			targetIndex,
			fmt.Sprintf("rekey from %s to %s is not allowed by cosigner rekey_policy", txn.Sender, txn.RekeyTo),
		)}
	}
	return nil
}

func cosignerRekeyViolation(targetIndex int, message string) policy.LintViolation {
	return policy.LintViolation{
		RuleID:   policy.CosignerRekeyRuleID,
		Scope:    "txn",
		TxnIndex: targetIndex,
		Message:  message,
	}
}

func withTargetIndex(violations []policy.LintViolation, targetIndex int) []policy.LintViolation {
	for i := range violations {
		violations[i].TxnIndex = targetIndex
	}
	return violations
}
