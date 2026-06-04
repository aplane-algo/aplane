// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/policy"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func (s *Service) evaluateAttestorComponentPolicy(identityID string, plan *ComponentSignPlan) *ServiceError {
	if plan == nil {
		return internal("component sign plan is nil")
	}
	cfg := attestationPolicyConfig(s.AttestationPolicy, plan.ComponentKey)
	if cfg == nil {
		return s.rejectAttestorComponentPolicy(identityID, plan, []policy.LintViolation{{
			RuleID:   policy.AttestationPolicyMissingRuleID,
			Scope:    "group",
			TxnIndex: -1,
			Message:  "attestation policy is not configured",
		}})
	}
	if cfg.TransferPolicy == nil || !cfg.TransferPolicy.Enabled {
		return s.rejectAttestorComponentPolicy(identityID, plan, []policy.LintViolation{{
			RuleID:   policy.AttestationTransferPolicyRequiredRuleID,
			Scope:    "group",
			TxnIndex: -1,
			Message:  "attestation.transfer_policy.enabled:true is required",
		}})
	}
	if violations := attestorTransferPolicyConfigLints(cfg.TransferPolicy); len(violations) > 0 {
		return s.rejectAttestorComponentPolicy(identityID, plan, violations)
	}

	var violations []policy.LintViolation
	for _, target := range plan.Targets {
		txn := plan.Group.Entries[target.TargetIndex].Txn
		violations = append(violations, attestorTargetPolicyLints(txn, target.TargetIndex, cfg)...)
	}
	if len(violations) > 0 {
		return s.rejectAttestorComponentPolicy(identityID, plan, violations)
	}
	return nil
}

func attestationPolicyConfig(cfg *policy.Config, componentKey string) *policy.Config {
	if cfg == nil {
		return nil
	}
	return cfg.ForKey(componentKey)
}

func attestorTransferPolicyConfigLints(tp *policy.TransferPolicy) []policy.LintViolation {
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
			RuleID:   policy.AttestationDeterministicRoutingRuleID,
			Scope:    "group",
			TxnIndex: -1,
			Message:  fmt.Sprintf("attestation transfer_policy.%s must be reject, got %q", check.field, check.value),
		})
	}
	return violations
}

func attestorTargetPolicyLints(txn types.Transaction, targetIndex int, cfg *policy.Config) []policy.LintViolation {
	var violations []policy.LintViolation
	if len(policy.ExtractTransferMovements(txn)) == 0 {
		violations = append(violations, policy.LintViolation{
			RuleID:   policy.AttestationNonTransferRuleID,
			Scope:    "txn",
			TxnIndex: targetIndex,
			Message:  fmt.Sprintf("attestation policy only supports direct pay and axfer targets, got %s", txn.Type),
		})
	}
	if cfg.RejectRekey && !txn.RekeyTo.IsZero() {
		violations = append(violations, policy.LintViolation{
			RuleID:   policy.AttestationRekeyRuleID,
			Scope:    "txn",
			TxnIndex: targetIndex,
			Message:  "rekey transactions are rejected by attestation policy",
		})
	}

	commonLintCfg := cfg.Clone()
	commonLintCfg.RejectForeignRekey = false
	commonLintCfg.RejectRekey = false
	violations = append(violations, withTargetIndex(
		policy.CheckTxnPolicyLintsWithKnownAddresses(txn, txn.Sender.String(), commonLintCfg, nil),
		targetIndex,
	)...)
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

func withTargetIndex(violations []policy.LintViolation, targetIndex int) []policy.LintViolation {
	for i := range violations {
		violations[i].TxnIndex = targetIndex
	}
	return violations
}

func (s *Service) rejectAttestorComponentPolicy(identityID string, plan *ComponentSignPlan, violations []policy.LintViolation) *ServiceError {
	reason := policy.JoinLintViolations(violations)
	if reason == "" {
		reason = "attestation policy rejected request"
	}
	s.logAttestorPolicyRejections(identityID, plan, reason, firstPolicyRuleID(violations))
	return forbidden("attestation policy rejected request: " + reason)
}

func firstPolicyRuleID(violations []policy.LintViolation) string {
	if len(violations) == 0 {
		return ""
	}
	return violations[0].RuleID
}

func (s *Service) logAttestorPolicyRejections(identityID string, plan *ComponentSignPlan, reason, policyRuleID string) {
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
				ruleLogger.LogSignRejectedWithPolicyRule(identityID, plan.ComponentKey, sender, "attestation_policy_rejected: "+reason, policyRuleID)
				continue
			}
		}
		rejectLogger.LogSignRejected(identityID, plan.ComponentKey, sender, "attestation_policy_rejected: "+reason)
	}
}

func (s *Service) logAttestorComponentApproved(identityID string, plan *ComponentSignPlan, result *ComponentSignResult) {
	if s.AuditLog == nil || plan == nil || result == nil {
		return
	}
	componentKey := result.ComponentKey
	if componentKey == "" {
		componentKey = plan.ComponentKey
	}
	for _, target := range plan.Targets {
		s.AuditLog.LogSignApproved(
			identityID,
			componentKey,
			target.Sender,
			fmt.Sprintf("attestor component signature target %d signed", target.TargetIndex),
		)
	}
}
