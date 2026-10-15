// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/witness"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// evaluateCosignerComponentPolicy applies the cosigner key's policy (its own
// document, or the node default) to every target. A cosigner has no operator,
// so every verdict is sign or reject: a review verdict, which the document
// format cannot express on a cosigner node, is treated as a rejection.
func (s *Service) evaluateCosignerComponentPolicy(plan *ComponentSignPlan) *ServiceError {
	if plan == nil {
		return internal("component sign plan is nil")
	}
	componentKey, err := witness.NormalizeID(plan.ComponentKey)
	if err != nil {
		return badRequest(err.Error())
	}
	if s.HoldsCosignerKey == nil || !s.HoldsCosignerKey(componentKey) {
		return badRequest(fmt.Sprintf("Witness Key ID %q not found", componentKey))
	}
	cfg := s.policyFor(componentKey)
	if cfg == nil {
		return internal("policy is not loaded")
	}

	// Known-network gate: every signing path refuses a transaction whose
	// genesis hash names no network this node knows, before any policy rule.
	// Asset references are only meaningful on a known network; the gate
	// applies to every transaction, including ones that name no asset (a
	// cosigner rekey is a 0 ALGO self-payment), so no path has to prove it
	// cannot carry one. A cosigner has no operator, so the refusal is an
	// audited policy rejection rather than a bare bad request.
	resolver := s.genesisHashResolver()
	var violations []policy.LintViolation
	for _, target := range plan.Targets {
		txn := plan.Group.Entries[target.TargetIndex].Txn
		if _, ok := resolver.NetworkForGenesisHashBytes(txn.GenesisHash[:]); !ok {
			violations = append(violations, policy.LintViolation{
				RuleID:   policy.UnknownGenesisHashRuleID,
				Scope:    "txn",
				TxnIndex: target.TargetIndex,
				Message:  fmt.Sprintf("cannot evaluate cosigner policy for unknown genesis hash %x", txn.GenesisHash[:]),
			})
			continue
		}
		violations = append(violations, cosignerTargetPolicyLints(txn, target.TargetIndex, cfg)...)
	}
	if len(violations) > 0 {
		return s.rejectCosignerComponentPolicy(plan, violations)
	}
	return nil
}

func cosignerTargetPolicyLints(txn types.Transaction, targetIndex int, cfg *policy.Config) []policy.LintViolation {
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
		policy.CheckTxnTransferRoutingPolicyLints(txn, cfg, false),
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
		policy.CheckTxnTransferRoutingReviewPolicyLints(txn, cfg, false),
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

func (s *Service) rejectCosignerComponentPolicy(plan *ComponentSignPlan, violations []policy.LintViolation) *ServiceError {
	reason := policy.JoinLintViolations(violations)
	if reason == "" {
		reason = "cosigner policy rejected request"
	}
	s.logCosignerPolicyRejections(plan, reason, firstPolicyRuleID(violations))
	return forbidden("cosigner policy rejected request: " + reason)
}

func firstPolicyRuleID(violations []policy.LintViolation) string {
	if len(violations) == 0 {
		return ""
	}
	return violations[0].RuleID
}

func (s *Service) logCosignerPolicyRejections(plan *ComponentSignPlan, reason, policyRuleID string) {
	rejectLogger, ok := s.AuditLog.(policyAuditLogger)
	if !ok || rejectLogger == nil || plan == nil {
		return
	}
	for _, target := range plan.Targets {
		sender := target.Sender
		if sender == "" && plan.Group != nil && target.TargetIndex >= 0 && target.TargetIndex < len(plan.Group.Entries) {
			sender = plan.Group.Entries[target.TargetIndex].Txn.Sender.String()
		}
		if limited, ok := s.AuditLog.(AuditCosignerRejectLogger); ok && limited != nil {
			limited.LogCosignerComponentRejected(plan.ComponentKey, sender, "cosigner_policy_rejected: "+reason, policyRuleID)
			continue
		}
		if policyRuleID != "" {
			if ruleLogger, ok := s.AuditLog.(AuditRejectPolicyRuleLogger); ok && ruleLogger != nil {
				ruleLogger.LogSignRejectedWithPolicyRule(plan.ComponentKey, sender, "cosigner_policy_rejected: "+reason, policyRuleID)
				continue
			}
		}
		rejectLogger.LogSignRejected(plan.ComponentKey, sender, "cosigner_policy_rejected: "+reason)
	}
}

func (s *Service) logCosignerComponentApproved(plan *ComponentSignPlan, result *ComponentSignResult) {
	if s.AuditLog == nil || plan == nil || result == nil {
		return
	}
	componentKey := result.ComponentKey
	if componentKey == "" {
		componentKey = plan.ComponentKey
	}
	for _, target := range plan.Targets {
		s.AuditLog.LogSignApproved(componentKey,
			target.Sender,
			fmt.Sprintf("cosigner component signature target %d signed", target.TargetIndex),
		)
	}
}

// genesisHashResolver is the node's network map, shared with /sign planning.
// A zero resolver resolves the built-in networks only.
func (s *Service) genesisHashResolver() apconfig.GenesisHashNetworkResolver {
	if s == nil || s.Planner == nil {
		return apconfig.GenesisHashNetworkResolver{}
	}
	return s.Planner.GenesisHashResolver
}

// componentPlanTxns returns every transaction in a component plan's group.
func componentPlanTxns(plan *ComponentSignPlan) []types.Transaction {
	if plan == nil || plan.Group == nil {
		return nil
	}
	txns := make([]types.Transaction, len(plan.Group.Entries))
	for i, entry := range plan.Group.Entries {
		txns[i] = entry.Txn
	}
	return txns
}
