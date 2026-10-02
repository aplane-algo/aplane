// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/witness"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

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
	cfg, ok := s.CosignerPolicies[componentKey]
	if !ok || cfg == nil {
		return s.rejectCosignerComponentPolicy(plan, []policy.LintViolation{{
			RuleID:   policy.CosignerKeyHasNoPolicyRuleID,
			Scope:    "group",
			TxnIndex: -1,
			Message:  fmt.Sprintf("cosigner key %s has no policy", componentKey),
		}})
	}
	if cfg.TransferPolicy == nil || !cfg.TransferPolicy.Enabled {
		return s.rejectCosignerComponentPolicy(plan, []policy.LintViolation{{
			RuleID:   policy.CosignerTransferPolicyRequiredRuleID,
			Scope:    "group",
			TxnIndex: -1,
			Message:  "cosigner.transfer_policy.enabled:true is required",
		}})
	}
	if violations := cosignerTransferPolicyConfigLints(cfg.TransferPolicy); len(violations) > 0 {
		return s.rejectCosignerComponentPolicy(plan, violations)
	}

	var violations []policy.LintViolation
	for _, target := range plan.Targets {
		txn := plan.Group.Entries[target.TargetIndex].Txn
		violations = append(violations, cosignerTargetPolicyLints(txn, target.TargetIndex, cfg)...)
	}
	if len(violations) > 0 {
		return s.rejectCosignerComponentPolicy(plan, violations)
	}
	return nil
}

func cosignerTransferPolicyConfigLints(tp *policy.TransferPolicy) []policy.LintViolation {
	if tp == nil {
		return nil
	}
	checks := []struct {
		field string
		value policy.TransferOnNoRoute
	}{
		{field: "on_no_route", value: tp.OnNoRoute},
		{field: "close_on_no_route", value: tp.CloseOnNoRoute},
		{field: "clawback_on_no_route", value: tp.ClawbackOnNoRoute},
	}
	var violations []policy.LintViolation
	for _, check := range checks {
		if check.value == policy.TransferOnNoRouteReject {
			continue
		}
		violations = append(violations, policy.LintViolation{
			RuleID:   policy.CosignerDeterministicRoutingRuleID,
			Scope:    "group",
			TxnIndex: -1,
			Message:  fmt.Sprintf("cosigner transfer_policy.%s must be reject, got %q", check.field, check.value),
		})
	}
	return violations
}

func cosignerTargetPolicyLints(txn types.Transaction, targetIndex int, cfg *policy.Config) []policy.LintViolation {
	var violations []policy.LintViolation
	isRekey := !txn.RekeyTo.IsZero()
	if !isRekey && len(policy.ExtractTransferMovements(txn)) == 0 {
		violations = append(violations, policy.LintViolation{
			RuleID:   policy.CosignerNonTransferRuleID,
			Scope:    "txn",
			TxnIndex: targetIndex,
			Message:  fmt.Sprintf("cosigner policy only supports direct pay and axfer targets, got %s", txn.Type),
		})
	}
	commonLintCfg := cfg.Clone()
	commonLintCfg.RejectForeignRekey = false
	commonLintCfg.RejectRekey = false
	violations = append(violations, withTargetIndex(
		policy.CheckTxnPolicyLints(txn, commonLintCfg, nil),
		targetIndex,
	)...)
	if isRekey {
		if cfg.RejectRekey {
			violations = append(violations, policy.LintViolation{
				RuleID:   policy.CosignerRekeyRuleID,
				Scope:    "txn",
				TxnIndex: targetIndex,
				Message:  "rekey transactions are rejected by cosigner policy",
			})
			return violations
		}
		violations = append(violations, cosignerRekeyPolicyLints(txn, targetIndex, cfg)...)
		return violations
	}
	violations = append(violations, withTargetIndex(
		policy.CheckTxnTransferRoutingPolicyLints(txn, cfg, false),
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
